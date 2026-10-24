//! Transaction **policy** (relay / mempool admission), separate from block consensus.
//!
//! Policy checks may reject mempool acceptance. They must **never** be invoked
//! from block connect / confirm paths.
//!
//! # Libre-relay-class admission
//!
//! This is the only mempool admit policy. Reject consensus failure, DoS
//! resource limits, and reserved upgrade hooks. Defaults: **0.1 sat/vB**
//! min relay, **no dust limit** (1-sat OK; 0-value spendable is dust), full
//! RBF, Libre annex.

use bitcoin::{Transaction, Weight};

/// Minimum relay feerate: **0.1 sat/vB** = 100 sat/kvB.
pub const MIN_RELAY_FEE_RATE_SAT_PER_KVB: u64 = 100;

/// Absolute weight cap for a single transaction (4_000_000 = block weight).
pub const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;

/// Result of a policy check (not consensus).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyResult {
    Standard,
    NonStandard(&'static str),
}

impl PolicyResult {
    pub fn is_standard(&self) -> bool {
        matches!(self, PolicyResult::Standard)
    }

    pub fn is_ok(&self) -> bool {
        self.is_standard()
    }
}

/// `(weight + 3) / 4`.
///
/// `Weight::to_vbytes_ceil` is `(wu + 4) - 1`, and the `+ 4` panics in
/// debug and wraps in release when `wu > u64::MAX - 4`. Sigop adjustment
/// saturates at `u64::MAX` (unknown cost until recompute), which would
/// become a tiny vsize. That range takes `u64::MAX / 4`, the same result
/// as `saturating_add(3) / 4`.
pub fn vbytes_ceil(weight: u64) -> u64 {
    if weight > u64::MAX - 4 {
        return u64::MAX / 4;
    }
    Weight::from_wu(weight).to_vbytes_ceil()
}

/// Zero `max_sat_vb` is unlimited. Otherwise the fee is over
/// `max_sat_vb * vbytes_ceil(weight)`.
pub fn fee_exceeds_max(fee_sat: u64, weight: u64, max_sat_vb: u64) -> bool {
    if max_sat_vb == 0 {
        return false;
    }
    fee_sat > max_sat_vb.saturating_mul(vbytes_ceil(weight))
}

/// True if `fee_sat` meets the minimum relay feerate for `weight` (WU).
///
/// Uses integer compare: `fee * 1000 >= vsize * MIN_RELAY_FEE_RATE_SAT_PER_KVB`.
pub fn meets_min_relay_fee(fee_sat: u64, weight: u64) -> bool {
    meets_min_relay_fee_at(fee_sat, weight, MIN_RELAY_FEE_RATE_SAT_PER_KVB)
}

/// Same as [`meets_min_relay_fee`] with an explicit sat/kvB floor (`0` = no floor).
pub fn meets_min_relay_fee_at(fee_sat: u64, weight: u64, sat_kvb: u64) -> bool {
    if sat_kvb == 0 {
        return true;
    }
    let vsize = vbytes_ceil(weight);
    if vsize == 0 {
        return false;
    }
    fee_sat.saturating_mul(1000) >= vsize.saturating_mul(sat_kvb)
}

/// Feerate in sat/kvB for diagnostics (floors).
pub fn fee_rate_sat_per_kvb(fee_sat: u64, weight: u64) -> u64 {
    let vsize = vbytes_ceil(weight);
    if vsize == 0 {
        return 0;
    }
    fee_sat.saturating_mul(1000) / vsize
}

/// Libre annex rule ([`IsAnnexStandard`](https://github.com/bitcoin/bitcoin) Libre Relay):
///
/// - No annex / empty payload after `0x50` tag → OK  
/// - Non-empty annex only if the **first data byte after the tag is `0x00`**  
///
/// `annex` is the full witness stack element (including leading `0x50` when present).
pub fn is_annex_standard(annex: &[u8]) -> bool {
    if annex.is_empty() {
        return true;
    }
    if annex[0] != 0x50 {
        return true;
    }
    annex.len() == 1 || annex[1] == 0x00
}

/// Scan inputs for a BIP341 annex and apply the Libre annex rule.
///
/// BIP341: annex is the **last** witness stack item only when `stack.len() ≥ 2`
/// and that item begins with `0x50`. A lone stack item (key-path signature) is
/// never an annex even if it happens to start with `0x50`.
pub fn check_libre_annex(tx: &Transaction) -> PolicyResult {
    for inp in &tx.input {
        let stack = inp.witness.to_vec();
        if stack.len() < 2 {
            continue;
        }
        let Some(last) = stack.last() else {
            continue;
        };
        if !is_annex_standard(last) {
            return PolicyResult::NonStandard("libre annex");
        }
    }
    PolicyResult::Standard
}

/// Core `CScript::IsUnspendable`: leading `OP_RETURN`, or over `MAX_SCRIPT_SIZE`.
pub fn is_unspendable(script: &[u8]) -> bool {
    script.first() == Some(&0x6a)
        || script.len() > crate::script::interpreter::MAX_SCRIPT_SIZE_LEGACY
}

/// A 0-value output that can enter the UTXO set. `OP_RETURN` is not one.
pub fn is_zero_value_spendable(out: &bitcoin::TxOut) -> bool {
    out.value.to_sat() == 0 && !is_unspendable(out.script_pubkey.as_bytes())
}

/// Libre has no dust *limit*; a 0-value spendable output is still dust.
pub fn zero_value_spendable_is_dust(tx: &Transaction) -> bool {
    tx.output.iter().any(is_zero_value_spendable)
}

/// Libre admission for a single tx given fee and weight (no dust limit, no template ban).
///
/// Callers still enforce consensus, cluster limits, and DoS caps separately.
pub fn check_libre_admission(tx: &Transaction, fee_sat: u64, weight: u64) -> PolicyResult {
    check_libre_admission_at(tx, fee_sat, weight, MIN_RELAY_FEE_RATE_SAT_PER_KVB)
}

/// Libre admission with an explicit min-relay floor (Core `-minrelaytxfee`).
/// Shape checks that do not need a fee or parent outputs.
pub fn check_libre_shape(tx: &Transaction, weight: u64) -> PolicyResult {
    check_libre_shape_inner(tx, weight, false)
}

/// Same shape rules, but one 0-value spendable output is not dust.
///
/// The caller has already required a 0 fee and a child that spends it.
pub fn check_libre_shape_allow_ephemeral(tx: &Transaction, weight: u64) -> PolicyResult {
    check_libre_shape_inner(tx, weight, true)
}

fn check_libre_shape_inner(tx: &Transaction, weight: u64, allow_ephemeral: bool) -> PolicyResult {
    if tx.is_coinbase() {
        return PolicyResult::NonStandard("coinbase");
    }
    if tx.output.iter().any(|o| {
        let spk = o.script_pubkey.as_bytes();
        spk.len() > crate::script::interpreter::MAX_SCRIPT_SIZE_LEGACY && spk.first() != Some(&0x6a)
    }) {
        return PolicyResult::NonStandard("scriptpubkey");
    }
    if tx.input.is_empty() {
        return PolicyResult::NonStandard("no inputs");
    }
    if tx.output.is_empty() {
        return PolicyResult::NonStandard("no outputs");
    }
    let zeros = tx
        .output
        .iter()
        .filter(|o| is_zero_value_spendable(o))
        .count();
    if zeros > 1 || (zeros == 1 && !allow_ephemeral) {
        return PolicyResult::NonStandard("dust");
    }
    if weight > MAX_STANDARD_TX_WEIGHT {
        return PolicyResult::NonStandard("tx weight");
    }
    check_libre_annex(tx)
}

pub fn check_libre_admission_at(
    tx: &Transaction,
    fee_sat: u64,
    weight: u64,
    min_relay_sat_kvb: u64,
) -> PolicyResult {
    match check_libre_shape(tx, weight) {
        PolicyResult::Standard => {}
        other => return other,
    }
    if !meets_min_relay_fee_at(fee_sat, weight, min_relay_sat_kvb) {
        return PolicyResult::NonStandard("min relay fee");
    }
    PolicyResult::Standard
}
