//! `OP_CHECKTEMPLATEVERIFY` on the default signet.
//!
//! BIP 119 is `OP_CHECKTEMPLATEVERIFY` (`OP_NOP4`, `0xb3`). Bitcoin
//! Inquisition activates it with one `nVersion` signal, then the rule stays
//! on. This port uses the buried height that signal produced. It does not
//! watch for a later abandon block: none has been mined, and a future
//! abandon would deactivate the rule in Inquisition while this code kept
//! enforcing it.
//!
//! Regtest turns the opcode on at every height, matching Inquisition regtest.
//! Mainnet, testnet, and a custom signet challenge stay off. Only the default
//! signet challenge inherits the height.

use crate::params::ChainParams;
use bitcoin::Network;

/// First block where `OP_CHECKTEMPLATEVERIFY` is enforced on the default signet.
pub const SIGNET_CTV_HEIGHT: u32 = 106_704;

/// `OP_CHECKTEMPLATEVERIFY` enforced for one block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HereticalFlags {
    pub ctv: bool,
}

impl HereticalFlags {
    /// Opcode off. Usable from `const` flag constructors.
    pub const OFF: Self = Self { ctv: false };
}

/// Flags for `height` on `params`.
pub fn flags_at(params: &ChainParams, height: u32) -> HereticalFlags {
    if params.network == Network::Regtest {
        return HereticalFlags { ctv: true };
    }
    if !is_default_signet(params) {
        return HereticalFlags::default();
    }
    HereticalFlags {
        ctv: height >= SIGNET_CTV_HEIGHT,
    }
}

fn is_default_signet(params: &ChainParams) -> bool {
    let Some(challenge) = params.signet_challenge.as_ref() else {
        return false;
    };
    challenge.as_bytes() == crate::signet::default_signet_challenge().as_bytes()
}
