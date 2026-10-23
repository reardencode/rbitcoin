//! BIP 448 on the default signet.
//!
//! BIP 448 is three tapscript opcodes: [`OP_TEMPLATEHASH`][th],
//! [`OP_CHECKSIGFROMSTACK`][csfs], and [`OP_INTERNALKEY`][ik]. Bitcoin
//! Inquisition activates them with one `nVersion` signal each, then the rule
//! stays on. This port uses those buried heights. It does not watch for a
//! later abandon block: none has been mined, and a future abandon would
//! deactivate the rule in Inquisition while this code kept enforcing it.
//!
//! Regtest turns the three opcodes on at every height, matching Inquisition
//! regtest. Mainnet, testnet, and a custom signet challenge stay off. Only
//! the default signet challenge inherits the heights. BIP 448 leaves mainnet
//! activation unspecified, and this crate does not pick one.
//!
//! [th]: https://github.com/bitcoin/bips/blob/master/bip-0446.mediawiki
//! [csfs]: https://github.com/bitcoin/bips/blob/master/bip-0348.mediawiki
//! [ik]: https://github.com/bitcoin/bips/blob/master/bip-0349.mediawiki

use crate::params::ChainParams;
use bitcoin::Network;

/// First block of each BIP 448 opcode on the default signet.
pub const SIGNET_CSFS_HEIGHT: u32 = 272_592;
pub const SIGNET_INTERNALKEY_HEIGHT: u32 = 272_592;
pub const SIGNET_TEMPLATEHASH_HEIGHT: u32 = 314_928;

/// Opcodes enforced for one block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HereticalFlags {
    pub csfs: bool,
    pub internal_key: bool,
    pub template_hash: bool,
}

impl HereticalFlags {
    /// Every opcode off. Usable from `const` flag constructors.
    pub const OFF: Self = Self {
        csfs: false,
        internal_key: false,
        template_hash: false,
    };
}

/// Flags for `height` on `params`.
pub fn flags_at(params: &ChainParams, height: u32) -> HereticalFlags {
    if params.network == Network::Regtest {
        return HereticalFlags {
            csfs: true,
            internal_key: true,
            template_hash: true,
        };
    }
    if !is_default_signet(params) {
        return HereticalFlags::default();
    }
    HereticalFlags {
        csfs: height >= SIGNET_CSFS_HEIGHT,
        internal_key: height >= SIGNET_INTERNALKEY_HEIGHT,
        template_hash: height >= SIGNET_TEMPLATEHASH_HEIGHT,
    }
}

fn is_default_signet(params: &ChainParams) -> bool {
    let Some(challenge) = params.signet_challenge.as_ref() else {
        return false;
    };
    challenge.as_bytes() == crate::signet::default_signet_challenge().as_bytes()
}
