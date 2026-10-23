//! BIP 54 consensus cleanup on the default signet.
//!
//! Bitcoin Inquisition activates the cleanup with one `nVersion` signal, then
//! the rule stays on. This port uses the buried height that signal produced.
//! It does not watch for a later abandon block: none has been mined, and a
//! future abandon would deactivate the rule in Inquisition while this code
//! kept enforcing it.
//!
//! Regtest leaves the cleanup off. Inquisition regtest does enforce it.
//! rbitcoin's regtest miner and the existing suite emit Core coinbases
//! (`nLockTime` 0, `nSequence` final), which the cleanup rejects.
//!
//! Mainnet, testnet, and a custom signet challenge stay off. Only the default
//! signet challenge inherits the height.

use crate::error::ConsensusError;
use crate::params::ChainParams;
use bitcoin::Network;

/// First block where BIP 54 consensus cleanup is enforced on the default signet.
pub const SIGNET_CLEANUP_HEIGHT: u32 = 291_168;

/// A difficulty-adjustment block's timestamp must be at least this close to
/// its parent (two hours).
pub const MAX_TIMEWARP_BIP54: i64 = 2 * 60 * 60;

/// Unscaled legacy sigops executed by one transaction.
pub const MAX_TX_BIP54_SIGOPS: u64 = 2500;

/// Witness-stripped transaction size BIP 54 rejects inside a block.
pub const INVALID_TX_NONWITNESS_SIZE: usize = 64;

/// Consensus cleanup enforced for one block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HereticalFlags {
    pub consensus_cleanup: bool,
}

impl HereticalFlags {
    /// Cleanup off. Usable from `const` flag constructors.
    pub const OFF: Self = Self {
        consensus_cleanup: false,
    };
}

/// Flags for `height` on `params`.
pub fn flags_at(params: &ChainParams, height: u32) -> HereticalFlags {
    if params.network == Network::Regtest || !is_default_signet(params) {
        return HereticalFlags::default();
    }
    HereticalFlags {
        consensus_cleanup: height >= SIGNET_CLEANUP_HEIGHT,
    }
}

fn is_default_signet(params: &ChainParams) -> bool {
    let Some(challenge) = params.signet_challenge.as_ref() else {
        return false;
    };
    challenge.as_bytes() == crate::signet::default_signet_challenge().as_bytes()
}

/// Height of the first block of the difficulty period, when BIP 54's
/// negative-interval check applies to `height`. `None` when the check is off
/// or this block is not the last of a period.
pub fn period_open_height(params: &ChainParams, height: u32) -> Option<u32> {
    if !flags_at(params, height).consensus_cleanup {
        return None;
    }
    let interval = params.difficulty_adjustment_interval();
    if interval <= 1 || height % interval != interval - 1 || height < interval - 1 {
        return None;
    }
    Some(height - (interval - 1))
}

/// BIP 54 header time rules. Call only when consensus cleanup is active.
///
/// A first-of-period block must be at least [`MAX_TIMEWARP_BIP54`] seconds
/// after its parent, using `i64` subtraction. A last-of-period block must be
/// at least as late as `period_open_time`. `None` on that block fails closed.
pub fn bip54_header_time(
    parent_time: u32,
    header_time: u32,
    height: u32,
    interval: u32,
    period_open_time: Option<u32>,
) -> Result<(), ConsensusError> {
    if interval == 0 {
        return Ok(());
    }
    if height.is_multiple_of(interval) {
        let parent = i64::from(parent_time);
        let header = i64::from(header_time);
        if header < parent - MAX_TIMEWARP_BIP54 {
            return Err(ConsensusError::BadHeader("time-timewarp-attack"));
        }
    }
    if interval > 1 && height % interval == interval - 1 {
        let open =
            period_open_time.ok_or(ConsensusError::BadHeader("missing bip54 period open"))?;
        if header_time < open {
            return Err(ConsensusError::BadHeader("time-negative-interval"));
        }
    }
    Ok(())
}
