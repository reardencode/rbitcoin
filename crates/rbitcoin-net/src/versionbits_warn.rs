//! Unknown-versionbits activation warnings (Core `WarningBitsConditionChecker`).
//!
//! Mainnet: period 2016, threshold 1815 (90%). Regtest/testnets: period =
//! difficulty interval, threshold = 75% of period. Blocks below the network's
//! `MinBIP9WarningHeight` are not counted. When a completed period has
//! ≥threshold counted blocks signalling an unassigned bit with BIP9 top bits,
//! the next tip reports `Unknown new rules activated (versionbit N)`.

use rbitcoin_primitives::{Height, Network};
use rbitcoin_query::Query;
use std::sync::Mutex;

#[doc(hidden)]
pub const VERSIONBITS_TOP_BITS: u32 = 0x2000_0000;
#[doc(hidden)]
pub const VERSIONBITS_TOP_MASK: u32 = 0xe000_0000;
#[doc(hidden)]
/// BIP 323: only bits 0–4 can warn. Bits 5–28 are reserved and stay quiet.
pub const VERSIONBITS_NUM_BITS: i32 = 5;

/// Period / threshold for unknown-bit warnings.
pub fn warn_period_threshold(network: Network) -> (u32, u32) {
    match network {
        Network::Mainnet => (2016, 1815),
        Network::Testnet | Network::Signet => (2016, 2016 * 3 / 4),
        Network::Regtest => (144, 144 * 3 / 4),
        Network::Testnet4 => unimplemented!("testnet4 versionbits"),
    }
}

/// Blocks below this height are not counted (Core `MinBIP9WarningHeight`).
pub fn warn_min_height(network: Network) -> u32 {
    match network {
        Network::Mainnet => 711_648,
        Network::Testnet => 2_013_984,
        Network::Signet | Network::Regtest => 0,
        Network::Testnet4 => unimplemented!("testnet4 versionbits"),
    }
}

/// Format Core's unknown-rules warning for `bit`.
pub fn unknown_rules_warning(bit: i32) -> String {
    format!("Unknown new rules activated (versionbit {bit})")
}

/// Unknown bits that reached ACTIVE on the best chain, kept across calls.
///
/// A bit locked in during period `p` is ACTIVE from period `p + 2`, and
/// ACTIVE is final, so each completed period is read once and only periods
/// completed since the last call are read. RAM is a few words; the trade is
/// one header pass per new period instead of 5 passes from genesis per RPC
/// call (≈4.7 s per `getnetworkinfo` at mainnet height 968k).
pub struct UnknownBitsScan {
    /// Periods `0..scanned_periods` are counted.
    pub scanned_periods: u32,
    /// Hash of the last header of the last counted period (reorg check).
    pub boundary: [u8; 32],
    /// Bits that reached the threshold in a counted period.
    pub locked: u32,
}

impl UnknownBitsScan {
    #[doc(hidden)]
    pub const fn new() -> Self {
        Self {
            scanned_periods: 0,
            boundary: [0; 32],
            locked: 0,
        }
    }

    pub fn active_bits(&mut self, query: &Query, network: Network) -> Vec<i32> {
        let Some(tip) = query.tip_height() else {
            return Vec::new();
        };
        let (period, threshold) = warn_period_threshold(network);
        self.advance(query, tip.0, period, threshold, warn_min_height(network))
    }

    #[doc(hidden)]
    pub fn advance(
        &mut self,
        query: &Query,
        tip: u32,
        period: u32,
        threshold: u32,
        min_height: u32,
    ) -> Vec<i32> {
        // The most recent completed period is at most LOCKED_IN, not ACTIVE.
        let target = (tip / period).saturating_sub(1);
        if target < self.scanned_periods || !self.boundary_matches(query, period) {
            self.scanned_periods = 0;
            self.boundary = [0; 32];
            self.locked = 0;
        }
        for p in self.scanned_periods..target {
            let mut counts = [0u32; VERSIONBITS_NUM_BITS as usize];
            for h in (p * period).max(min_height).max(1)..(p + 1) * period {
                if let Ok(Some((_, rec))) = query.header_at_height(Height(h)) {
                    for (bit, count) in counts.iter_mut().enumerate() {
                        if signals_unknown(&rec.version, bit as i32) {
                            *count += 1;
                        }
                    }
                }
            }
            for (bit, count) in counts.iter().enumerate() {
                if *count >= threshold {
                    self.locked |= 1 << bit;
                }
            }
        }
        if target > self.scanned_periods {
            self.scanned_periods = target;
            self.boundary = query
                .header_at_height(Height(period_boundary_height(target, period)))
                .ok()
                .flatten()
                .map_or([0; 32], |(_, rec)| rec.hash);
        }
        (0..VERSIONBITS_NUM_BITS)
            .filter(|bit| (self.locked >> bit) & 1 == 1)
            .collect()
    }

    #[doc(hidden)]
    pub fn boundary_matches(&self, query: &Query, period: u32) -> bool {
        if self.scanned_periods == 0 {
            return true;
        }
        let h = period_boundary_height(self.scanned_periods, period);
        matches!(query.header_at_height(Height(h)), Ok(Some((_, rec))) if rec.hash == self.boundary)
    }
}

/// Last header of a prefix of `periods` counted periods (`periods * period - 1`).
#[doc(hidden)]
pub fn period_boundary_height(periods: u32, period: u32) -> u32 {
    periods * period - 1
}

#[doc(hidden)]
pub fn signals_unknown(version: &i32, bit: i32) -> bool {
    let v = *version as u32;
    (v & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS && ((v >> bit) & 1) != 0
}

/// Unknown-version-bit warnings. This is the list `-alertnotify` watches.
pub fn versionbit_warning_strings(query: &Query, network: Network) -> Vec<String> {
    static SCAN: Mutex<UnknownBitsScan> = Mutex::new(UnknownBitsScan::new());
    SCAN.lock()
        .unwrap_or_else(|e| e.into_inner())
        .active_bits(query, network)
        .into_iter()
        .map(unknown_rules_warning)
        .collect()
}

/// The standing trust-peer line. Absent when the mode is off, including when
/// a label is passed. It is not a version-bit alert.
pub fn trust_warning_line(query: &Query, trust_who: Option<&str>) -> Option<String> {
    if !query.trust_peer() {
        return None;
    }
    trust_who.map(|who| format!("disagreements from trust-peer {who} are warnings"))
}
