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

use bitcoin::Transaction;

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

/// Virtual size in vbytes: `(weight + 3) / 4`.
#[inline]
pub fn get_virtual_size(weight: u64) -> u64 {
    weight.saturating_add(3) / 4
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
    let vsize = get_virtual_size(weight);
    if vsize == 0 {
        return false;
    }
    fee_sat.saturating_mul(1000) >= vsize.saturating_mul(sat_kvb)
}

/// Feerate in sat/kvB for diagnostics (floors).
pub fn fee_rate_sat_per_kvb(fee_sat: u64, weight: u64) -> u64 {
    let vsize = get_virtual_size(weight);
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
        if !last.is_empty() && last[0] == 0x50 && !is_annex_standard(last) {
            return PolicyResult::NonStandard("libre annex");
        }
    }
    PolicyResult::Standard
}

/// Core `CScript::IsUnspendable`: leading `OP_RETURN`, or over `MAX_SCRIPT_SIZE`.
pub fn is_unspendable(script: &[u8]) -> bool {
    script.first() == Some(&0x6a) || script.len() > 10_000
}

/// Libre has no dust *limit*; a 0-value spendable output is still dust.
pub fn zero_value_spendable_is_dust(tx: &Transaction) -> bool {
    tx.output
        .iter()
        .any(|o| o.value.to_sat() == 0 && !is_unspendable(o.script_pubkey.as_bytes()))
}

/// Libre admission for a single tx given fee and weight (no dust limit, no template ban).
///
/// Callers still enforce consensus, cluster limits, and DoS caps separately.
pub fn check_libre_admission(tx: &Transaction, fee_sat: u64, weight: u64) -> PolicyResult {
    check_libre_admission_at(tx, fee_sat, weight, MIN_RELAY_FEE_RATE_SAT_PER_KVB)
}

/// Libre admission with an explicit min-relay floor (Core `-minrelaytxfee`).
pub fn check_libre_admission_at(
    tx: &Transaction,
    fee_sat: u64,
    weight: u64,
    min_relay_sat_kvb: u64,
) -> PolicyResult {
    if tx.is_coinbase() {
        return PolicyResult::NonStandard("coinbase");
    }
    if tx.input.is_empty() {
        return PolicyResult::NonStandard("no inputs");
    }
    if tx.output.is_empty() {
        return PolicyResult::NonStandard("no outputs");
    }
    if zero_value_spendable_is_dust(tx) {
        return PolicyResult::NonStandard("dust");
    }
    if weight > MAX_STANDARD_TX_WEIGHT {
        return PolicyResult::NonStandard("tx weight");
    }
    if !meets_min_relay_fee_at(fee_sat, weight, min_relay_sat_kvb) {
        return PolicyResult::NonStandard("min relay fee");
    }
    check_libre_annex(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    #[test]
    fn min_relay_fee_point_one_sat_vb() {
        // 1000 vB → weight 4000; 0.1 sat/vB → 100 sat min.
        assert!(meets_min_relay_fee(100, 4000));
        assert!(!meets_min_relay_fee(99, 4000));
        assert_eq!(fee_rate_sat_per_kvb(100, 4000), 100);
        assert!(meets_min_relay_fee_at(1, 4000, 0));
        assert!(!meets_min_relay_fee_at(1, 4000, 100));
    }

    #[test]
    fn annex_libre_rules() {
        assert!(is_annex_standard(&[]));
        assert!(is_annex_standard(&[0x50]));
        assert!(is_annex_standard(&[0x50, 0x00]));
        assert!(is_annex_standard(&[0x50, 0x00, 0xab]));
        assert!(!is_annex_standard(&[0x50, 0x01]));
        assert!(!is_annex_standard(&[0x50, 0xff, 0x00]));
    }

    fn bare_tx(fee_out: u64) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([1u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(fee_out),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]), // OP_TRUE — dust-ish / nonstd OK under Libre
            }],
        }
    }

    #[test]
    fn libre_allows_op_true_and_dust_outputs() {
        // weight of bare_tx is small; fee = 50_000 - 1 = large enough.
        let tx = bare_tx(1);
        let weight = tx.weight().to_wu();
        // pretend input value 50_000
        let fee = 50_000u64.saturating_sub(1);
        assert!(check_libre_admission(&tx, fee, weight).is_ok());

        let zero = bare_tx(0);
        assert_eq!(
            check_libre_admission(&zero, 50_000, zero.weight().to_wu()),
            PolicyResult::NonStandard("dust")
        );
        let mut opreturn = bare_tx(0);
        opreturn.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x00]);
        assert!(check_libre_admission(&opreturn, 50_000, opreturn.weight().to_wu()).is_ok());
    }

    #[test]
    fn libre_rejects_low_feerate() {
        let tx = bare_tx(50_000);
        let weight = tx.weight().to_wu();
        assert_eq!(
            check_libre_admission(&tx, 0, weight),
            PolicyResult::NonStandard("min relay fee")
        );
    }

    #[test]
    fn libre_rejects_bad_annex() {
        let mut tx = bare_tx(1);
        tx.input[0].witness = Witness::from_slice(&[vec![0x01], vec![0x50, 0x01]]);
        let weight = tx.weight().to_wu();
        assert_eq!(
            check_libre_admission(&tx, 50_000, weight),
            PolicyResult::NonStandard("libre annex")
        );
    }

    #[test]
    fn policy_result_is_ok_alias() {
        assert!(PolicyResult::Standard.is_ok());
        assert!(!PolicyResult::NonStandard("x").is_ok());
    }

    #[test]
    fn vsize_fee_zero_and_libre_gates() {
        assert!(!meets_min_relay_fee(1, 0));
        assert_eq!(fee_rate_sat_per_kvb(100, 0), 0);
        assert_eq!(get_virtual_size(1), 1);

        // Coinbase rejected.
        let cb = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x00, 0x01]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(50),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        assert_eq!(
            check_libre_admission(&cb, 0, 100),
            PolicyResult::NonStandard("coinbase")
        );

        // No inputs / no outputs.
        let mut no_in = bare_tx(1);
        no_in.input.clear();
        assert_eq!(
            check_libre_admission(&no_in, 1000, 100),
            PolicyResult::NonStandard("no inputs")
        );
        let mut no_out = bare_tx(1);
        no_out.output.clear();
        assert_eq!(
            check_libre_admission(&no_out, 1000, 100),
            PolicyResult::NonStandard("no outputs")
        );

        // Weight cap.
        let tx = bare_tx(1);
        assert_eq!(
            check_libre_admission(&tx, 1_000_000, MAX_STANDARD_TX_WEIGHT + 1),
            PolicyResult::NonStandard("tx weight")
        );

        // Annex not tagged 0x50 is ignored by is_annex_standard.
        assert!(is_annex_standard(&[0x01, 0x02]));
        // Libre annex scan: non-annex last item is fine.
        let mut ok = bare_tx(1);
        ok.input[0].witness = Witness::from_slice(&[vec![0x01], vec![0x02]]);
        assert!(check_libre_annex(&ok).is_standard());
    }
}
