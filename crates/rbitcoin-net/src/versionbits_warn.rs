//! Unknown-versionbits activation warnings (Core `WarningBitsConditionChecker`).
//!
//! Regtest/testnets: period = difficulty interval, threshold = 75% of period.
//! When a completed period has ≥threshold blocks signalling an unassigned bit
//! with BIP9 top bits, the next tip reports
//! `Unknown new rules activated (versionbit N)`.

use rbitcoin_primitives::{Height, Network};
use rbitcoin_query::Query;

const VERSIONBITS_TOP_BITS: u32 = 0x2000_0000;
const VERSIONBITS_TOP_MASK: u32 = 0xe000_0000;
const VERSIONBITS_NUM_BITS: i32 = 29;

/// Period / threshold for unknown-bit warnings (Core test-chain rule).
pub fn warn_period_threshold(network: Network) -> (u32, u32) {
    let period = match network {
        Network::Regtest => 144,
        Network::Testnet | Network::Signet => 2016,
        Network::Mainnet => 2016,
    };
    let threshold = period * 3 / 4;
    (period, threshold)
}

/// Format Core's unknown-rules warning for `bit`.
pub fn unknown_rules_warning(bit: i32) -> String {
    format!("Unknown new rules activated (versionbit {bit})")
}

/// Scan best-chain headers for unknown bits that reached ACTIVE.
pub fn active_unknown_bits(query: &Query, network: Network) -> Vec<i32> {
    let Some(tip_h) = query.tip_height() else {
        return Vec::new();
    };
    let tip = tip_h.0;
    if tip == 0 {
        return Vec::new();
    }
    let (period, threshold) = warn_period_threshold(network);
    // Need at least two full periods after genesis to have an ACTIVE state
    // (LOCKED_IN in period N, ACTIVE from start of period N+1).
    if tip < period * 2 {
        return Vec::new();
    }
    let mut active = Vec::new();
    for bit in 0..VERSIONBITS_NUM_BITS {
        if bit_is_active(query, tip, period, threshold, bit) {
            active.push(bit);
        }
    }
    active
}

fn bit_is_active(query: &Query, tip: u32, period: u32, threshold: u32, bit: i32) -> bool {
    // Walk completed periods ending at period boundaries ≤ tip.
    // ACTIVE if some period P had ≥threshold signalling and tip is in a later period.
    let periods_done = tip / period;
    if periods_done < 2 {
        return false;
    }
    // Check the period that ended at (periods_done-1)*period — if it locked in,
    // we are ACTIVE in the current period.
    // Period p covers heights [p*period, (p+1)*period). LOCKED_IN after a
    // signalling period; ACTIVE once tip reaches the following period.
    for p in 0..periods_done.saturating_sub(1) {
        let start = p * period;
        let end_excl = (p + 1) * period;
        let mut count = 0u32;
        for h in start..end_excl {
            if h == 0 {
                continue;
            }
            if let Ok(Some((_, rec))) = query.header_at_height(Height(h)) {
                if signals_unknown(&rec.version, bit) {
                    count += 1;
                }
            }
        }
        if count >= threshold && tip >= (p + 2) * period {
            return true;
        }
    }
    false
}
fn signals_unknown(version: &i32, bit: i32) -> bool {
    let v = *version as u32;
    (v & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS && ((v >> bit) & 1) != 0
}

/// Warning strings for RPC `warnings` arrays.
pub fn warning_strings(query: &Query, network: Network) -> Vec<String> {
    active_unknown_bits(query, network)
        .into_iter()
        .map(unknown_rules_warning)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regtest_period_matches_core_functional() {
        let (p, t) = warn_period_threshold(Network::Regtest);
        assert_eq!(p, 144);
        assert_eq!(t, 108);
    }

    #[test]
    fn warning_text_matches_core() {
        assert_eq!(
            unknown_rules_warning(27),
            "Unknown new rules activated (versionbit 27)"
        );
    }

    #[test]
    fn top_bits_signal_detection() {
        let v = (VERSIONBITS_TOP_BITS | (1 << 27)) as i32;
        assert!(signals_unknown(&v, 27));
        assert!(!signals_unknown(&v, 26));
        assert!(!signals_unknown(&(VERSIONBITS_TOP_BITS as i32), 27));
    }
}
