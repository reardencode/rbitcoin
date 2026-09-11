//! BIP-352 Silent Payments **tweak server** (scan-side `A_tweak` only).
//!
//! libsecp256k1 has a `silentpayments` C module; rust-secp256k1 0.29 (bitcoin
//! 0.32) does not bind it. This module uses `PublicKey::combine_keys` +
//! `mul_tweak` plus script extract. We never take a scan private key.

use bitcoin::hashes::{hash160, sha256, Hash, HashEngine};
use bitcoin::key::{Parity, XOnlyPublicKey};
use bitcoin::script::{Instruction, Script};
use bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1};
use bitcoin::{OutPoint, Transaction, TxOut, Witness};
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::Query;
use rbitcoin_store::{InputRecord, OutputRecord, StoreError};
use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

use crate::error::ConsensusError;
use crate::params::ChainParams;

/// BIP341 NUMS internal key *H* (SHA256 of uncompressed *G* as x-only).
const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// One Taproot output listed for Electrum tweaks `output_pubkeys`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaprootOut {
    pub vout: u32,
    pub xonly: [u8; 32],
    pub value: u64,
}

/// Server tweak plus Taproot outs for one eligible tx.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxTweak {
    /// `input_hash · ΣA` — 33-byte compressed.
    pub tweak: [u8; 33],
    pub output_pubkeys: Vec<TaprootOut>,
}

fn secp() -> &'static Secp256k1<All> {
    static S: OnceLock<Secp256k1<All>> = OnceLock::new();
    S.get_or_init(Secp256k1::new)
}

/// Compute the BIP-352 server tweak for `tx` given prevout scripts.
///
/// `prevouts.len()` must equal `tx.input.len()`. Returns `None` if the tx is
/// not silent-payment eligible (or the pubkey sum is infinity / invalid hash).
pub fn tweak_from_tx(tx: &Transaction, prevouts: &[TxOut]) -> Option<TxTweak> {
    if tx.input.len() != prevouts.len() {
        return None;
    }
    let output_pubkeys = taproot_outs(tx);
    if output_pubkeys.is_empty() {
        return None;
    }
    if prevouts
        .iter()
        .any(|p| witness_version(p.script_pubkey.as_bytes()) > Some(1))
    {
        return None;
    }

    let mut keys = Vec::new();
    for (vin, prev) in tx.input.iter().zip(prevouts.iter()) {
        if let Some(pk) = extract_input_pubkey(
            prev.script_pubkey.as_script(),
            vin.script_sig.as_script(),
            &vin.witness,
        ) {
            keys.push(pk);
        }
    }
    if keys.is_empty() {
        return None;
    }
    let refs: Vec<&PublicKey> = keys.iter().collect();
    let a = PublicKey::combine_keys(&refs).ok()?;
    let tweak = input_hash_mul_a(tx, &a)?;
    Some(TxTweak {
        tweak,
        output_pubkeys,
    })
}

/// Prefer the thin index (no parent peeks). Hole / no table → [`tweaks_for_height`].
pub fn tweaks_at_height(
    query: &Query,
    params: &ChainParams,
    height: Height,
) -> Result<BTreeMap<[u8; 32], TxTweak>, ConsensusError> {
    if !params.taproot_active_at(height.0) {
        return Ok(BTreeMap::new());
    }
    match query.load_thin_tweaks(height) {
        Ok(Some(rows)) => {
            let mut out = BTreeMap::new();
            for r in rows {
                out.insert(
                    r.txid,
                    TxTweak {
                        tweak: r.tweak,
                        output_pubkeys: r
                            .p2tr
                            .into_iter()
                            .map(|(vout, xonly, value)| TaprootOut { vout, xonly, value })
                            .collect(),
                    },
                );
            }
            return Ok(out);
        }
        Ok(None) => {
            rbitcoin_log::debug!(
                "sp_tweaks: naive fallback h={} (hole or index off)",
                height.0
            );
        }
        Err(e) => return Err(e.into()),
    }
    tweaks_for_height(query, params, height)
}

/// Sequential hole fill from the table’s next height through **live** tip.
///
/// Re-reads tip after each snapshot so tip-follow during backfill does not
/// leave a tail. Stop when `next_height > tip`. Safe to resume after kill
/// (`next_height` is the last complete `put`).
pub fn backfill_sp_tweaks(query: &Query, params: &ChainParams) -> Result<u32, ConsensusError> {
    backfill_sp_tweaks_cancellable(query, params, None)
}

#[allow(clippy::type_complexity)] // packed row / pin / script-hash tuple is the on-disk shape
/// Like [`backfill_sp_tweaks`], stopping when `cancel` is set (process exit).
pub fn backfill_sp_tweaks_cancellable(
    query: &Query,
    params: &ChainParams,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<u32, ConsensusError> {
    if !query.sptweaks_enabled() {
        return Ok(0);
    }
    let origin = query.sptweaks_origin();
    let mut wrote = 0u32;
    const WRITE_BATCH: usize = 16;
    let t0 = std::time::Instant::now();
    let mut last_log = t0;
    let mut pending: Vec<(Height, Fk, Vec<Option<[u8; 33]>>)> = Vec::new();
    let flush = |pending: &mut Vec<(Height, Fk, Vec<Option<[u8; 33]>>)>,
                 wrote: &mut u32|
     -> Result<(), ConsensusError> {
        if pending.is_empty() {
            return Ok(());
        }
        let n = pending.len() as u32;
        query.put_sp_tweaks_blocks(pending)?;
        *wrote = wrote.saturating_add(n);
        pending.clear();
        Ok(())
    };
    loop {
        if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)) {
            flush(&mut pending, &mut wrote)?;
            return Ok(wrote);
        }
        let Some(tip) = query.tip_height() else {
            flush(&mut pending, &mut wrote)?;
            return Ok(wrote);
        };
        let mut h = query
            .sptweaks_next_height()
            .unwrap_or(origin)
            .0
            .max(origin.0);
        if h > tip.0 {
            flush(&mut pending, &mut wrote)?;
            return Ok(wrote);
        }
        let snapshot = tip.0;
        while h <= snapshot {
            if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)) {
                flush(&mut pending, &mut wrote)?;
                return Ok(wrote);
            }
            let height = Height(h);
            let Some(header_fk) = query.store().confirmed.get(height)? else {
                flush(&mut pending, &mut wrote)?;
                return Ok(wrote);
            };
            let fks = match query.block_tx_fks(height) {
                Ok(f) => f,
                Err(StoreError::NotFound) => {
                    flush(&mut pending, &mut wrote)?;
                    return Ok(wrote);
                }
                Err(e) => return Err(e.into()),
            };
            let map = tweaks_for_height(query, params, height)?;
            let mut recs = Vec::with_capacity(fks.len());
            for fk in fks {
                let txid = query.store().txs.body_txid(fk)?;
                recs.push(map.get(&txid).map(|t| t.tweak));
            }
            pending.push((height, header_fk, recs));
            if pending.len() >= WRITE_BATCH {
                flush(&mut pending, &mut wrote)?;
            }
            h = h.saturating_add(1);
            if last_log.elapsed() >= std::time::Duration::from_secs(10) {
                last_log = std::time::Instant::now();
                let next = h;
                let remain = snapshot.saturating_sub(next.saturating_sub(1));
                let secs = t0.elapsed().as_secs_f64().max(1e-3);
                let rate = wrote as f64 / secs;
                rbitcoin_log::info!(
                    "{}",
                    format_sptweaks_progress(next, snapshot, rate, remain, t0.elapsed())
                );
            }
        }
        flush(&mut pending, &mut wrote)?;
    }
}

pub(crate) fn format_sptweaks_progress(
    next: u32,
    tip: u32,
    rate: f64,
    remain: u32,
    elapsed: std::time::Duration,
) -> String {
    format!(
        "sptweaks: backfill next={next} tip={tip} rate={rate:.1}/s remain={remain} elapsed={elapsed:?}"
    )
}

/// Confirmed height → eligible txid (internal order) → tweak.
///
/// Pre-Taproot and missing heights return an empty map (no error). Does not
/// reconstruct a wire block. Walks packed bodies **and parent outs**.
pub fn tweaks_for_height(
    query: &Query,
    params: &ChainParams,
    height: Height,
) -> Result<BTreeMap<[u8; 32], TxTweak>, ConsensusError> {
    if !params.taproot_active_at(height.0) {
        return Ok(BTreeMap::new());
    }
    let fks = match query.block_tx_fks(height) {
        Ok(f) => f,
        Err(StoreError::NotFound) => return Ok(BTreeMap::new()),
        Err(e) => return Err(e.into()),
    };
    if fks.is_empty() {
        return Ok(BTreeMap::new());
    }

    let wave = rbitcoin_store::load_tweak_wave(&query.store().txs, &fks)?;
    let mut parent_outs: HashMap<Fk, Vec<OutputRecord>> = HashMap::new();
    let mut parent_txid: HashMap<Fk, [u8; 32]> = HashMap::new();
    for t in &wave.txs {
        parent_outs.insert(t.fk, t.outs.clone());
        parent_txid.insert(t.fk, t.rec.txid);
    }
    for (fk, (txid, outs)) in &wave.parents {
        parent_outs.entry(Fk(*fk)).or_insert_with(|| outs.clone());
        parent_txid.entry(Fk(*fk)).or_insert(*txid);
    }

    let mut jobs: Vec<([u8; 32], bitcoin::Transaction, Vec<TxOut>)> = Vec::new();
    for t in &wave.txs {
        if !t.need_inwit {
            continue;
        }
        let Some(inputs) = t.inputs.as_ref() else {
            continue;
        };
        let Some(built) = build_tx_and_prevouts(inputs, &t.outs, &parent_outs, &parent_txid) else {
            continue;
        };
        jobs.push((t.rec.txid, built.0, built.1));
    }
    if jobs.is_empty() {
        return Ok(BTreeMap::new());
    }
    let slots: Vec<OnceLock<Option<TxTweak>>> = (0..jobs.len()).map(|_| OnceLock::new()).collect();
    let idxs: Vec<usize> = (0..jobs.len()).collect();
    crate::script_pool::try_for_each_parallel_idle(&idxs, |&i| {
        let _ = slots[i].set(tweak_from_tx(&jobs[i].1, &jobs[i].2));
        Ok(())
    })?;
    let mut out = BTreeMap::new();
    for (i, slot) in slots.iter().enumerate() {
        if let Some(tweak) = slot.get().and_then(|o| o.clone()) {
            out.insert(jobs[i].0, tweak);
        }
    }
    Ok(out)
}

#[allow(clippy::type_complexity)] // packed row / pin / script-hash tuple is the on-disk shape
/// Tweaks-wire `TxTweak` from a stored 33-byte tweak + this tx’s packed outs.
///
/// No parent IO. `Some(tweak)` with missing packed outs is corrupt.
pub fn tweaks_from_thin_and_body(
    rows: &[([u8; 32], Option<[u8; 33]>, Option<&[OutputRecord]>)],
) -> Result<BTreeMap<[u8; 32], TxTweak>, StoreError> {
    let mut out = BTreeMap::new();
    for (txid, tweak, outs) in rows {
        let Some(tweak) = tweak else {
            continue;
        };
        let Some(outs) = outs else {
            return Err(StoreError::Corrupt(
                "invariant: thin tweak missing packed body",
            ));
        };
        out.insert(
            *txid,
            TxTweak {
                tweak: *tweak,
                output_pubkeys: taproot_outs_from_records(outs),
            },
        );
    }
    Ok(out)
}

fn taproot_outs_from_records(outputs: &[OutputRecord]) -> Vec<TaprootOut> {
    let mut out = Vec::new();
    for (i, o) in outputs.iter().enumerate() {
        if !is_p2tr(&o.script) {
            continue;
        }
        if o.script.len() < 34 {
            continue;
        }
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&o.script[2..34]);
        let value = if o.value < 0 { 0 } else { o.value as u64 };
        out.push(TaprootOut {
            vout: i as u32,
            xonly,
            value,
        });
    }
    out
}

fn build_tx_and_prevouts(
    inputs: &[InputRecord],
    outputs: &[OutputRecord],
    parent_outs: &HashMap<Fk, Vec<OutputRecord>>,
    parent_txid: &HashMap<Fk, [u8; 32]>,
) -> Option<(Transaction, Vec<TxOut>)> {
    let mut prevouts = Vec::with_capacity(inputs.len());
    let mut txins = Vec::with_capacity(inputs.len());
    for inp in inputs {
        let (prev_txid, prev_script, prev_value) = if inp.is_coinbase() {
            ([0u8; 32], Vec::new(), 0i64)
        } else {
            let tid = *parent_txid.get(&inp.create_fk)?;
            let outs = parent_outs.get(&inp.create_fk)?;
            let o = outs.get(inp.prev_index as usize)?;
            (tid, o.script.clone(), o.value)
        };
        let wit_refs: Vec<&[u8]> = inp.witness.iter().map(|w| w.as_slice()).collect();
        txins.push(bitcoin::TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array(prev_txid),
                vout: inp.prev_index,
            },
            script_sig: bitcoin::ScriptBuf::from_bytes(inp.script_sig.clone()),
            sequence: bitcoin::Sequence::from_consensus(inp.sequence),
            witness: Witness::from_slice(&wit_refs),
        });
        let value = if prev_value < 0 {
            bitcoin::Amount::ZERO
        } else {
            bitcoin::Amount::from_sat(prev_value as u64)
        };
        prevouts.push(TxOut {
            value,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(prev_script),
        });
    }
    let mut txouts = Vec::with_capacity(outputs.len());
    for o in outputs {
        let value = if o.value < 0 {
            bitcoin::Amount::ZERO
        } else {
            bitcoin::Amount::from_sat(o.value as u64)
        };
        txouts.push(TxOut {
            value,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(o.script.clone()),
        });
    }
    Some((
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: txins,
            output: txouts,
        },
        prevouts,
    ))
}

fn input_hash_mul_a(tx: &Transaction, a: &PublicKey) -> Option<[u8; 33]> {
    let mut smallest = outpoint_bytes(&tx.input[0].previous_output);
    for vin in tx.input.iter().skip(1) {
        let b = outpoint_bytes(&vin.previous_output);
        if b < smallest {
            smallest = b;
        }
    }
    let ser_a = a.serialize();
    let mut msg = [0u8; 36 + 33];
    msg[..36].copy_from_slice(&smallest);
    msg[36..].copy_from_slice(&ser_a);
    let h = tagged_hash(b"BIP0352/Inputs", &msg);
    if h == [0u8; 32] {
        return None;
    }
    let scalar = Scalar::from_be_bytes(h).ok()?;
    let tweaked = a.mul_tweak(secp(), &scalar).ok()?;
    Some(tweaked.serialize())
}

fn tagged_hash(tag: &[u8], payload: &[u8]) -> [u8; 32] {
    let tagh = sha256::Hash::hash(tag);
    let mut eng = sha256::Hash::engine();
    eng.input(tagh.as_ref());
    eng.input(tagh.as_ref());
    eng.input(payload);
    sha256::Hash::from_engine(eng).to_byte_array()
}

fn outpoint_bytes(op: &OutPoint) -> [u8; 36] {
    let mut b = [0u8; 36];
    b[..32].copy_from_slice(op.txid.as_byte_array());
    b[32..].copy_from_slice(&op.vout.to_le_bytes());
    b
}

/// True when `tx` has at least one P2TR output (BIP-352 eligible to consider).
pub(crate) fn tx_has_p2tr_output(tx: &Transaction) -> bool {
    tx.output
        .iter()
        .any(|o| is_p2tr(o.script_pubkey.as_bytes()))
}

fn taproot_outs(tx: &Transaction) -> Vec<TaprootOut> {
    let mut out = Vec::new();
    for (i, o) in tx.output.iter().enumerate() {
        let spk = o.script_pubkey.as_bytes();
        if !is_p2tr(spk) {
            continue;
        }
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&spk[2..34]);
        out.push(TaprootOut {
            vout: i as u32,
            xonly,
            value: o.value.to_sat(),
        });
    }
    out
}

fn is_p2tr(spk: &[u8]) -> bool {
    spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20
}

fn is_p2wpkh(spk: &[u8]) -> bool {
    spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14
}

fn is_p2pkh(spk: &[u8]) -> bool {
    spk.len() == 25
        && spk[0] == 0x76
        && spk[1] == 0xa9
        && spk[2] == 0x14
        && spk[23] == 0x88
        && spk[24] == 0xac
}

fn is_p2sh(spk: &[u8]) -> bool {
    spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87
}

fn witness_version(spk: &[u8]) -> Option<u8> {
    if spk.len() < 4 || spk.len() > 42 {
        return None;
    }
    let version = match spk[0] {
        0x00 => 0u8,
        v @ 0x51..=0x60 => v - 0x50,
        _ => return None,
    };
    let n = spk[1] as usize;
    if !(2..=40).contains(&n) || spk.len() != 2 + n {
        return None;
    }
    Some(version)
}

fn extract_input_pubkey(
    prev: &Script,
    script_sig: &Script,
    witness: &Witness,
) -> Option<PublicKey> {
    let spk = prev.as_bytes();
    if is_p2tr(spk) {
        return extract_p2tr(spk, witness);
    }
    if is_p2wpkh(spk) {
        return last_compressed_witness_pubkey(witness);
    }
    if is_p2sh(spk) {
        if !is_p2sh_p2wpkh_redeem(script_sig) {
            return None;
        }
        return last_compressed_witness_pubkey(witness);
    }
    if is_p2pkh(spk) {
        return p2pkh_script_pubkey(spk, script_sig);
    }
    None
}

fn extract_p2tr(spk: &[u8], witness: &Witness) -> Option<PublicKey> {
    if nums_h_script_path(witness) {
        return None;
    }
    let xonly = XOnlyPublicKey::from_slice(&spk[2..34]).ok()?;
    // Even-Y lift (BIP340 / BIP-352 taproot inputs).
    Some(xonly.public_key(Parity::Even))
}

fn nums_h_script_path(witness: &Witness) -> bool {
    let items = witness_items_no_annex(witness);
    if items.len() < 2 {
        return false;
    }
    let cb = items[items.len() - 1];
    if cb.len() < 33 {
        return false;
    }
    cb[1..33] == NUMS_H
}

fn witness_items_no_annex(witness: &Witness) -> Vec<&[u8]> {
    let mut items: Vec<&[u8]> = witness.iter().collect();
    if items.len() >= 2 {
        if let Some(last) = items.last() {
            if !last.is_empty() && last[0] == 0x50 {
                items.pop();
            }
        }
    }
    items
}

fn last_compressed_witness_pubkey(witness: &Witness) -> Option<PublicKey> {
    let items = witness_items_no_annex(witness);
    let last = items.last()?;
    compressed_pubkey(last)
}

/// P2PKH scriptSigs are third-party malleable. Take the compressed key whose
/// HASH160 matches the prevout (BIP-352: parse even if the template is wrapped).
fn p2pkh_script_pubkey(spk: &[u8], script_sig: &Script) -> Option<PublicKey> {
    if spk.len() != 25 {
        return None;
    }
    let want = &spk[3..23];
    let mut last = None;
    for ins in script_sig.instructions() {
        let Ok(Instruction::PushBytes(b)) = ins else {
            continue;
        };
        if let Some(pk) = compressed_pubkey(b.as_bytes()) {
            let h = hash160::Hash::hash(&pk.serialize());
            if h.as_byte_array() == want {
                last = Some(pk);
            }
        }
    }
    last
}

fn compressed_pubkey(b: &[u8]) -> Option<PublicKey> {
    if b.len() == 33 && (b[0] == 0x02 || b[0] == 0x03) {
        PublicKey::from_slice(b).ok()
    } else {
        None
    }
}

fn is_p2sh_p2wpkh_redeem(script_sig: &Script) -> bool {
    let mut push: Option<Vec<u8>> = None;
    let mut n = 0usize;
    for ins in script_sig.instructions() {
        match ins {
            Ok(Instruction::PushBytes(b)) => {
                n += 1;
                push = Some(b.as_bytes().to_vec());
            }
            Ok(_) => return false,
            Err(_) => return false,
        }
    }
    if n != 1 {
        return false;
    }
    let Some(r) = push else {
        return false;
    };
    r.len() == 22 && r[0] == 0x00 && r[1] == 0x14
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Milestone;
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, Sequence, TxIn};
    use rbitcoin_query::testutil::FixtureChain;
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, TxRecord};
    use serde_json::Value;
    use std::str::FromStr;
    fn hex_bytes(s: &str) -> Vec<u8> {
        rbitcoin_primitives::hex_decode(s).expect("hex")
    }

    fn decode_witness(s: &str) -> Witness {
        if s.is_empty() {
            return Witness::new();
        }
        let b = hex_bytes(s);
        deserialize::<Witness>(&b).unwrap_or_else(|_| Witness::from_slice(&[&b]))
    }

    fn tx_from_receiving(given: &Value) -> (Transaction, Vec<TxOut>) {
        let vin = given["vin"].as_array().expect("vin");
        let mut input = Vec::new();
        let mut prevouts = Vec::new();
        for v in vin {
            let txid = bitcoin::Txid::from_str(v["txid"].as_str().unwrap()).unwrap();
            let vout = v["vout"].as_u64().unwrap() as u32;
            let script_sig =
                ScriptBuf::from_bytes(hex_bytes(v["scriptSig"].as_str().unwrap_or("")));
            let wit = match &v["txinwitness"] {
                Value::String(s) => decode_witness(s),
                Value::Array(items) => {
                    let stacks: Vec<Vec<u8>> = items
                        .iter()
                        .filter_map(|x| x.as_str().map(hex_bytes))
                        .collect();
                    let refs: Vec<&[u8]> = stacks.iter().map(|s| s.as_slice()).collect();
                    Witness::from_slice(&refs)
                }
                _ => Witness::new(),
            };
            input.push(TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig,
                sequence: Sequence::MAX,
                witness: wit,
            });
            let prev_hex = v["prevout"]["scriptPubKey"]["hex"].as_str().unwrap();
            prevouts.push(TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(hex_bytes(prev_hex)),
            });
        }
        let mut output = Vec::new();
        if let Some(outs) = given["outputs"].as_array() {
            for o in outs {
                let x = hex_bytes(o.as_str().unwrap());
                assert_eq!(x.len(), 32);
                let mut spk = vec![0x51, 0x20];
                spk.extend_from_slice(&x);
                output.push(TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: ScriptBuf::from_bytes(spk),
                });
            }
        }
        if output.is_empty() {
            output.push(TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes({
                    let mut s = vec![0x51, 0x20];
                    s.extend_from_slice(&[0u8; 32]);
                    s
                }),
            });
        }
        (
            Transaction {
                version: TxVersion::TWO,
                lock_time: LockTime::ZERO,
                input,
                output,
            },
            prevouts,
        )
    }

    #[test]
    fn format_sptweaks_progress_has_operator_tokens() {
        let line = super::format_sptweaks_progress(
            800_000,
            963_000,
            25.0,
            163_000,
            std::time::Duration::from_secs(90),
        );
        assert!(line.contains("next=800000"), "{line}");
        assert!(line.contains("tip=963000"), "{line}");
        assert!(line.contains("rate=25.0/s"), "{line}");
        assert!(line.contains("remain=163000"), "{line}");
    }

    #[test]
    fn official_vectors_receiving_tweaks() {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/bip352_send_and_receive_test_vectors.json"
        ));
        let cases: Value = serde_json::from_str(raw).expect("vectors json");
        let mut n = 0u32;
        for case in cases.as_array().unwrap() {
            let comment = case["comment"].as_str().unwrap_or("");
            for rec in case["receiving"].as_array().unwrap() {
                let given = &rec["given"];
                let expected = &rec["expected"];
                let (tx, prev) = tx_from_receiving(given);
                let got = tweak_from_tx(&tx, &prev);
                match expected.get("tweak") {
                    Some(Value::String(exp)) => {
                        let t = got.unwrap_or_else(|| panic!("expected tweak for {comment}"));
                        assert_eq!(
                            rbitcoin_primitives::hex_encode(t.tweak),
                            exp.to_ascii_lowercase(),
                            "tweak mismatch: {comment}"
                        );
                        n += 1;
                    }
                    _ => {
                        assert!(
                            got.is_none(),
                            "expected skip for {comment}, got {:?}",
                            got.map(|g| rbitcoin_primitives::hex_encode(g.tweak))
                        );
                        n += 1;
                    }
                }
            }
        }
        assert!(n >= 28, "ran {n} receiving cases");
    }

    #[test]
    fn skip_witness_v2_input() {
        let tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes({
                    let mut s = vec![0x51, 0x20];
                    s.extend_from_slice(&[1u8; 32]);
                    s
                }),
            }],
        };
        let mut v2 = vec![0x52, 0x14];
        v2.extend_from_slice(&[0u8; 20]);
        let prev = vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(v2),
        }];
        assert!(tweak_from_tx(&tx, &prev).is_none());
    }

    fn tmp_store() -> (rbitcoin_query::testutil::TempDir, Query) {
        rbitcoin_query::testutil::tiny_query_labeled("sp-tweaks")
    }

    fn header(h: u32, prev_fk: Fk, prev_hash: Option<[u8; 32]>) -> HeaderRecord {
        let mut merkle = [0u8; 32];
        merkle[0..4].copy_from_slice(&h.to_le_bytes());
        merkle[5] = 0xec;
        let hash = match prev_hash {
            None => merkle,
            Some(ph) => rbitcoin_store::block_header_hash(1, &ph, &merkle, h + 1, 0x207f_ffff, h),
        };
        HeaderRecord {
            prev_fk,
            version: 1,
            timestamp: h + 1,
            bits: 0x207f_ffff,
            nonce: h,
            merkle_root: merkle,
            hash,
        }
    }

    #[test]
    fn tweaks_for_height_p2wpkh_parent_matches_engine() {
        use bitcoin::hashes::hash160;
        use bitcoin::secp256k1::SecretKey;

        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();

        let secp_ctx = Secp256k1::new();
        let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp_ctx, &sk);
        let ser = pk.serialize();
        let h160 = hash160::Hash::hash(&ser);
        let mut p2wpkh = vec![0x00, 0x14];
        p2wpkh.extend_from_slice(h160.as_ref());
        let (xonly, _) = pk.x_only_public_key();
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&xonly.serialize());

        let mut genesis_txid = [0u8; 32];
        genesis_txid[31] = 0xcb;
        let h0 = header(0, Fk::NULL, None);
        let ta0 = TxApply {
            tx: TxRecord {
                txid: genesis_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord::coinbase(u32::MAX, vec![0x00], vec![])],
            outputs: vec![OutputRecord::unspent(50_0000_0000, p2wpkh.clone())],
        };
        let fk0 = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
        let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];

        let mut spend_txid = [0u8; 32];
        spend_txid[0] = 0x11;
        spend_txid[31] = 0xcd;
        let h1 = header(1, fk0, Some(h0.hash));
        let ta1 = TxApply {
            tx: TxRecord {
                txid: spend_txid,
                version: 2,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: genesis_txid,
                create_fk,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![vec![0u8; 64], ser.to_vec()],
            }],
            outputs: vec![OutputRecord::unspent(49_0000_0000, p2tr.clone())],
        };
        q.connect_block(Height(1), &h1, &[ta1]).unwrap();

        let empty0 = tweaks_for_height(&q, &params, Height(0)).unwrap();
        assert!(empty0.is_empty(), "coinbase is not eligible");

        let got = tweaks_for_height(&q, &params, Height(1)).unwrap();
        assert_eq!(got.len(), 1);
        let t = got.get(&spend_txid).expect("spend txid");

        let engine_tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array(genesis_txid),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[&[0u8; 64][..], &ser[..]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(p2tr),
            }],
        };
        let engine_prev = vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(p2wpkh),
        }];
        let expect = tweak_from_tx(&engine_tx, &engine_prev).unwrap();
        assert_eq!(t.tweak, expect.tweak);
        assert_eq!(t.output_pubkeys, expect.output_pubkeys);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn thin_compose_matches_engine_outs_without_parents() {
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        // Reuse the P2WPKH→P2TR spend from the walk test via a tiny local chain.
        use bitcoin::hashes::hash160;
        use bitcoin::secp256k1::SecretKey;
        let secp_ctx = Secp256k1::new();
        let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp_ctx, &sk);
        let ser = pk.serialize();
        let h160 = hash160::Hash::hash(&ser);
        let mut p2wpkh = vec![0x00, 0x14];
        p2wpkh.extend_from_slice(h160.as_ref());
        let (xonly, _) = pk.x_only_public_key();
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&xonly.serialize());
        let mut genesis_txid = [0u8; 32];
        genesis_txid[31] = 0xcb;
        let h0 = header(0, Fk::NULL, None);
        let fk0 = q
            .connect_block(
                Height(0),
                &h0,
                &[TxApply {
                    tx: TxRecord {
                        txid: genesis_txid,
                        version: 1,
                        locktime: 0,
                        input_start_fk: Fk::NULL,
                        input_count: 1,
                        output_start_fk: Fk::NULL,
                        output_count: 1,
                    },
                    inputs: vec![InputRecord::coinbase(u32::MAX, vec![0x00], vec![])],
                    outputs: vec![OutputRecord::unspent(50_0000_0000, p2wpkh.clone())],
                }],
            )
            .unwrap();
        let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];
        let mut spend_txid = [0u8; 32];
        spend_txid[0] = 0x11;
        spend_txid[31] = 0xcd;
        let h1 = header(1, fk0, Some(h0.hash));
        q.connect_block(
            Height(1),
            &h1,
            &[TxApply {
                tx: TxRecord {
                    txid: spend_txid,
                    version: 2,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 1,
                    output_start_fk: Fk::NULL,
                    output_count: 1,
                },
                inputs: vec![InputRecord {
                    prev_txid: genesis_txid,
                    create_fk,
                    prev_index: 0,
                    sequence: u32::MAX,
                    script_sig: vec![],
                    witness: vec![vec![0u8; 64], ser.to_vec()],
                }],
                outputs: vec![OutputRecord::unspent(49_0000_0000, p2tr.clone())],
            }],
        )
        .unwrap();

        let naive = tweaks_for_height(&q, &params, Height(1)).unwrap();
        let t = naive.get(&spend_txid).unwrap();
        let spend_fk = q.block_tx_fks(Height(1)).unwrap()[0];
        let (_rec, _ins, outs) = q.store().get_tx_full(spend_fk).unwrap();
        let composed =
            tweaks_from_thin_and_body(&[(spend_txid, Some(t.tweak), Some(outs.as_slice()))])
                .unwrap();
        let c = composed.get(&spend_txid).unwrap();
        assert_eq!(c.tweak, t.tweak);
        assert_eq!(c.output_pubkeys, t.output_pubkeys);

        let miss = tweaks_from_thin_and_body(&[(spend_txid, Some(t.tweak), None)]);
        assert!(
            matches!(miss, Err(StoreError::Corrupt(m)) if m.contains("invariant")),
            "got {miss:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backfill_cancellable_stops_before_walk() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        q.enter_direct_index_mode().unwrap();
        q.set_sptweaks_enabled(true, Height(0)).unwrap();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        crate::accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE)
            .unwrap();
        assert_eq!(q.sptweaks_next_height(), Some(Height(0)));
        let cancel = AtomicBool::new(true);
        assert_eq!(
            backfill_sp_tweaks_cancellable(&q, &params, Some(&cancel)).unwrap(),
            0
        );
        assert_eq!(q.sptweaks_next_height(), Some(Height(0)));
        cancel.store(false, Ordering::Relaxed);
        assert_eq!(
            backfill_sp_tweaks_cancellable(&q, &params, Some(&cancel)).unwrap(),
            1
        );
        assert_eq!(q.sptweaks_next_height(), Some(Height(1)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backfill_noop_when_flag_off() {
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        assert_eq!(backfill_sp_tweaks(&q, &params).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tweaks_for_height_unknown_is_empty() {
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        assert!(tweaks_for_height(&q, &params, Height(0))
            .unwrap()
            .is_empty());
        let main = ChainParams::mainnet();
        assert!(tweaks_for_height(&q, &main, Height(100))
            .unwrap()
            .is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn confirm_hook_writes_thin_and_reorg_truncates() {
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        q.set_sptweaks_enabled(true, Height(0)).unwrap();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        crate::accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE)
            .unwrap();
        assert_eq!(q.sptweaks_next_height(), Some(Height(1)));
        let thin0 = q.load_thin_tweaks(Height(0)).unwrap().expect("indexed");
        assert!(
            thin0.is_empty(),
            "coinbase is not eligible — no Class A join"
        );

        let b1 = crate::mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
        crate::accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE).unwrap();
        assert_eq!(q.sptweaks_next_height(), Some(Height(2)));

        q.disconnect_tip().unwrap();
        assert_eq!(q.sptweaks_next_height(), Some(Height(1)));
        assert!(q.load_thin_tweaks(Height(1)).unwrap().is_none());

        let b1b = crate::mine_empty_regtest(genesis.block_hash(), genesis.header.time + 601, 2);
        crate::accept_and_connect_block(&q, &params, Height(1), &b1b, Milestone::NONE).unwrap();
        assert_eq!(q.sptweaks_next_height(), Some(Height(2)));
        assert!(q.load_thin_tweaks(Height(1)).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn direct_confirm_does_not_index_tweaks() {
        use rbitcoin_query::IndexMode;
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        q.enter_direct_index_mode().unwrap();
        q.set_sptweaks_enabled(true, Height(0)).unwrap();
        assert_eq!(q.index_mode(), IndexMode::Direct);
        assert_eq!(q.sptweaks_next_height(), Some(Height(0)));

        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        crate::accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE)
            .unwrap();
        let b1 = crate::mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
        crate::accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE).unwrap();

        assert_eq!(
            q.sptweaks_next_height(),
            Some(Height(0)),
            "Direct IBD must not write-through tweaks"
        );
        assert!(
            q.load_thin_tweaks(Height(0)).unwrap().is_none(),
            "no thin row until post-IBD backfill"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backfill_after_direct_indexes_through_tip_then_tip_write_through() {
        use rbitcoin_query::IndexMode;
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        q.enter_direct_index_mode().unwrap();
        q.set_sptweaks_enabled(true, Height(0)).unwrap();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        crate::accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE)
            .unwrap();
        let b1 = crate::mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
        crate::accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE).unwrap();
        assert_eq!(q.sptweaks_next_height(), Some(Height(0)));

        let n = backfill_sp_tweaks(&q, &params).unwrap();
        assert_eq!(
            n, 2,
            "resume/restart backfill fills Direct gap origin..=tip"
        );
        assert_eq!(q.sptweaks_next_height(), Some(Height(2)));
        assert!(q.load_thin_tweaks(Height(0)).unwrap().is_some());
        assert!(q.load_thin_tweaks(Height(1)).unwrap().is_some());

        q.enter_tip_index_mode();
        assert_eq!(q.index_mode(), IndexMode::Tip);
        let b2 = crate::mine_empty_regtest(b1.block_hash(), b1.header.time + 600, 2);
        crate::accept_and_connect_block(&q, &params, Height(2), &b2, Milestone::NONE).unwrap();
        assert_eq!(
            q.sptweaks_next_height(),
            Some(Height(3)),
            "Tip write-through after backfill caught up"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tip_write_skips_when_next_lags_backfill_owns_the_hole() {
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        q.enter_direct_index_mode().unwrap();
        q.set_sptweaks_enabled(true, Height(0)).unwrap();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        crate::accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE)
            .unwrap();
        let b1 = crate::mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
        crate::accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE).unwrap();

        q.enter_tip_index_mode();
        let b2 = crate::mine_empty_regtest(b1.block_hash(), b1.header.time + 600, 2);
        crate::accept_and_connect_block(&q, &params, Height(2), &b2, Milestone::NONE).unwrap();
        assert_eq!(
            q.sptweaks_next_height(),
            Some(Height(0)),
            "Tip write must not put height 2 while next is 0"
        );

        let n = backfill_sp_tweaks(&q, &params).unwrap();
        assert_eq!(
            n, 3,
            "backfill fills origin..=live tip including skipped write"
        );
        assert_eq!(q.sptweaks_next_height(), Some(Height(3)));
        assert!(q.load_thin_tweaks(Height(2)).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn indexed_serve_matches_naive_without_parent_walk() {
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        q.set_sptweaks_enabled(true, Height(0)).unwrap();
        // Build the P2WPKH→P2TR spend via connect_block, then backfill.
        use bitcoin::hashes::hash160;
        use bitcoin::secp256k1::SecretKey;
        let secp_ctx = Secp256k1::new();
        let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp_ctx, &sk);
        let ser = pk.serialize();
        let h160 = hash160::Hash::hash(&ser);
        let mut p2wpkh = vec![0x00, 0x14];
        p2wpkh.extend_from_slice(h160.as_ref());
        let (xonly, _) = pk.x_only_public_key();
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&xonly.serialize());
        let mut genesis_txid = [0u8; 32];
        genesis_txid[31] = 0xcb;
        let h0 = header(0, Fk::NULL, None);
        let fk0 = q
            .connect_block(
                Height(0),
                &h0,
                &[TxApply {
                    tx: TxRecord {
                        txid: genesis_txid,
                        version: 1,
                        locktime: 0,
                        input_start_fk: Fk::NULL,
                        input_count: 1,
                        output_start_fk: Fk::NULL,
                        output_count: 1,
                    },
                    inputs: vec![InputRecord::coinbase(u32::MAX, vec![0x00], vec![])],
                    outputs: vec![OutputRecord::unspent(50_0000_0000, p2wpkh)],
                }],
            )
            .unwrap();
        let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];
        let mut spend_txid = [0u8; 32];
        spend_txid[0] = 0x11;
        spend_txid[31] = 0xcd;
        let h1 = header(1, fk0, Some(h0.hash));
        q.connect_block(
            Height(1),
            &h1,
            &[TxApply {
                tx: TxRecord {
                    txid: spend_txid,
                    version: 2,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 1,
                    output_start_fk: Fk::NULL,
                    output_count: 1,
                },
                inputs: vec![InputRecord {
                    prev_txid: genesis_txid,
                    create_fk,
                    prev_index: 0,
                    sequence: u32::MAX,
                    script_sig: vec![],
                    witness: vec![vec![0u8; 64], ser.to_vec()],
                }],
                outputs: vec![OutputRecord::unspent(49_0000_0000, p2tr)],
            }],
        )
        .unwrap();

        let naive = tweaks_for_height(&q, &params, Height(1)).unwrap();
        assert_eq!(naive.len(), 1);
        let n = backfill_sp_tweaks(&q, &params).unwrap();
        assert_eq!(n, 2);
        let rows = q.load_thin_tweaks(Height(1)).unwrap().expect("indexed");
        assert_eq!(
            rows.len(),
            1,
            "ineligible txs must not be joined from Class A"
        );
        assert_eq!(rows[0].txid, spend_txid);
        let indexed = tweaks_at_height(&q, &params, Height(1)).unwrap();
        assert_eq!(
            indexed.get(&spend_txid).unwrap().tweak,
            naive.get(&spend_txid).unwrap().tweak
        );
        assert_eq!(
            indexed.get(&spend_txid).unwrap().output_pubkeys,
            naive.get(&spend_txid).unwrap().output_pubkeys
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fat non-P2TR sibling must not change the P2TR tweak (txout-first filter).
    #[test]
    fn tweaks_for_height_skips_inwit_on_non_p2tr_sibling() {
        use bitcoin::hashes::hash160;
        use bitcoin::secp256k1::SecretKey;
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        let secp_ctx = Secp256k1::new();
        let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp_ctx, &sk);
        let ser = pk.serialize();
        let h160 = hash160::Hash::hash(&ser);
        let mut p2wpkh = vec![0x00, 0x14];
        p2wpkh.extend_from_slice(h160.as_ref());
        let (xonly, _) = pk.x_only_public_key();
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&xonly.serialize());
        let mut genesis_txid = [0u8; 32];
        genesis_txid[31] = 0xcb;
        let h0 = header(0, Fk::NULL, None);
        let fk0 = q
            .connect_block(
                Height(0),
                &h0,
                &[TxApply {
                    tx: TxRecord {
                        txid: genesis_txid,
                        version: 1,
                        locktime: 0,
                        input_start_fk: Fk::NULL,
                        input_count: 1,
                        output_start_fk: Fk::NULL,
                        output_count: 1,
                    },
                    inputs: vec![InputRecord::coinbase(u32::MAX, vec![0x00], vec![])],
                    outputs: vec![OutputRecord::unspent(50_0000_0000, p2wpkh)],
                }],
            )
            .unwrap();
        let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];
        let mut spend_txid = [0u8; 32];
        spend_txid[0] = 0x11;
        spend_txid[31] = 0xcd;
        let mut fat_txid = [0u8; 32];
        fat_txid[0] = 0x22;
        let fat_script = vec![0x51; 200];
        let h1 = header(1, fk0, Some(h0.hash));
        q.connect_block(
            Height(1),
            &h1,
            &[
                TxApply {
                    tx: TxRecord {
                        txid: fat_txid,
                        version: 1,
                        locktime: 0,
                        input_start_fk: Fk::NULL,
                        input_count: 1,
                        output_start_fk: Fk::NULL,
                        output_count: 1,
                    },
                    inputs: vec![InputRecord::coinbase(u32::MAX, vec![0xaa; 80], vec![])],
                    outputs: vec![OutputRecord::unspent(1, fat_script)],
                },
                TxApply {
                    tx: TxRecord {
                        txid: spend_txid,
                        version: 2,
                        locktime: 0,
                        input_start_fk: Fk::NULL,
                        input_count: 1,
                        output_start_fk: Fk::NULL,
                        output_count: 1,
                    },
                    inputs: vec![InputRecord {
                        prev_txid: genesis_txid,
                        create_fk,
                        prev_index: 0,
                        sequence: u32::MAX,
                        script_sig: vec![],
                        witness: vec![vec![0u8; 64], ser.to_vec()],
                    }],
                    outputs: vec![OutputRecord::unspent(49_0000_0000, p2tr)],
                },
            ],
        )
        .unwrap();

        let naive = tweaks_for_height(&q, &params, Height(1)).unwrap();
        assert_eq!(naive.len(), 1, "fat sibling must not be eligible");
        assert!(naive.contains_key(&spend_txid));
        assert!(!naive.contains_key(&fat_txid));
        let only = tweaks_for_height(&q, &params, Height(1)).unwrap();
        assert_eq!(
            only.get(&spend_txid).unwrap().tweak,
            naive.get(&spend_txid).unwrap().tweak
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
