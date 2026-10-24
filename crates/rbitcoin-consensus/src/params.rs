use std::str::FromStr;

use bitcoin::blockdata::constants;
use bitcoin::consensus::Params as BtcParams;
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::{BlockHash, Network, Target};
/// Height from which BIP34's ancestry no longer turns BIP30 off (Core).
pub const BIP34_IMPLIES_BIP30_LIMIT: u32 = 1_983_702;

#[doc(hidden)]
pub fn bip34_block_hash(display_hex: &str) -> BlockHash {
    BlockHash::from_str(display_hex).expect("BIP34 block hash")
}

/// Static chain parameters for validation.
#[derive(Debug, Clone)]
pub struct ChainParams {
    pub network: Network,
    pub genesis_hash: BlockHash,
    /// Core's `ConnectBlock` returns before adding the genesis block's
    /// coinbase to the coin view, so its outputs are never spendable.
    pub genesis_coinbase_txid: [u8; 32],
    pub pow_limit: Target,
    /// rust-bitcoin consensus params (retarget spacing, no_pow_retargeting, …).
    pub btc: BtcParams,
    /// BIP325 signet challenge script (`None` = not a signet).
    pub signet_challenge: Option<ScriptBuf>,
    /// `-testactivationheight=csv@H` overlay (`None` = network default).
    pub csv_height_overlay: Option<u32>,
    /// `-testactivationheight=segwit@H` overlay (`None` = network default).
    pub segwit_height_overlay: Option<u32>,
    /// Subsidy halving interval overlay (`None` = network default).
    pub subsidy_halving_overlay: Option<u32>,
    /// Header hash at BIP34 height that turns BIP30 off. `None` on signet and
    /// regtest (Core's null hash), so BIP30 stays on at every height.
    pub bip34_hash: Option<BlockHash>,
}

impl ChainParams {
    pub fn for_network(network: rbitcoin_primitives::Network) -> Self {
        match network {
            rbitcoin_primitives::Network::Mainnet => Self::mainnet(),
            rbitcoin_primitives::Network::Testnet => Self::testnet(),
            rbitcoin_primitives::Network::Signet => Self::signet(),
            rbitcoin_primitives::Network::Regtest => Self::regtest(),
        }
    }

    pub fn regtest() -> Self {
        let genesis = constants::genesis_block(Network::Regtest);
        let mut btc = BtcParams::new(Network::Regtest);
        // rust-bitcoin still carries Core's historical regtest heights
        // (BIP34=100_000_000, BIP65=1351, BIP66=1251). Core `CRegTestParams`
        // sets all three to 1.
        btc.bip34_height = 1;
        btc.bip65_height = 1;
        btc.bip66_height = 1;
        Self {
            network: Network::Regtest,
            genesis_hash: genesis.block_hash(),
            genesis_coinbase_txid: genesis.txdata[0].compute_txid().to_byte_array(),
            pow_limit: Target::MAX_ATTAINABLE_REGTEST,
            btc,
            signet_challenge: None,
            csv_height_overlay: None,
            segwit_height_overlay: None,
            subsidy_halving_overlay: None,
            bip34_hash: None,
        }
    }

    pub fn mainnet() -> Self {
        let genesis = constants::genesis_block(Network::Bitcoin);
        Self {
            network: Network::Bitcoin,
            genesis_hash: genesis.block_hash(),
            genesis_coinbase_txid: genesis.txdata[0].compute_txid().to_byte_array(),
            pow_limit: Target::MAX_ATTAINABLE_MAINNET,
            btc: BtcParams::new(Network::Bitcoin),
            signet_challenge: None,
            csv_height_overlay: None,
            segwit_height_overlay: None,
            subsidy_halving_overlay: None,
            bip34_hash: Some(bip34_block_hash(
                // Core `consensus.BIP34Hash`: mainnet block 227931.
                "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8",
            )),
        }
    }

    pub fn testnet() -> Self {
        let genesis = constants::genesis_block(Network::Testnet);
        Self {
            network: Network::Testnet,
            genesis_hash: genesis.block_hash(),
            genesis_coinbase_txid: genesis.txdata[0].compute_txid().to_byte_array(),
            pow_limit: Target::MAX_ATTAINABLE_TESTNET,
            btc: BtcParams::new(Network::Testnet),
            signet_challenge: None,
            csv_height_overlay: None,
            segwit_height_overlay: None,
            subsidy_halving_overlay: None,
            bip34_hash: Some(bip34_block_hash(
                "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8",
            )),
        }
    }

    pub fn signet() -> Self {
        Self::custom_signet(crate::signet::default_signet_challenge(), 10 * 60)
            .expect("default signet block time is nonzero")
    }

    /// Build custom BIP325 signet parameters.
    ///
    /// `block_time` changes PoW target spacing while retaining Signet's two-week
    /// target timespan, matching Bitcoin Core's `signetblocktime` behavior.
    pub fn custom_signet(challenge: ScriptBuf, block_time: u64) -> Result<Self, &'static str> {
        if block_time == 0 {
            return Err("signet block time must be greater than zero");
        }
        let genesis = constants::genesis_block(Network::Signet);
        let mut btc = BtcParams::new(Network::Signet);
        btc.pow_target_spacing = block_time;
        Ok(Self {
            network: Network::Signet,
            genesis_hash: genesis.block_hash(),
            genesis_coinbase_txid: genesis.txdata[0].compute_txid().to_byte_array(),
            pow_limit: Target::MAX_ATTAINABLE_SIGNET,
            btc,
            signet_challenge: Some(challenge),
            csv_height_overlay: None,
            segwit_height_overlay: None,
            subsidy_halving_overlay: None,
            bip34_hash: None,
        })
    }

    /// True for the genesis coinbase txid, which is never a coin.
    #[inline]
    pub fn is_genesis_coinbase(&self, txid: &[u8; 32]) -> bool {
        *txid == self.genesis_coinbase_txid
    }

    pub fn difficulty_adjustment_interval(&self) -> u32 {
        self.btc.difficulty_adjustment_interval() as u32
    }

    pub fn no_pow_retargeting(&self) -> bool {
        self.btc.no_pow_retargeting
    }

    pub fn allow_min_difficulty_blocks(&self) -> bool {
        self.btc.allow_min_difficulty_blocks
    }

    pub fn subsidy_halving_interval(&self) -> u32 {
        if let Some(n) = self.subsidy_halving_overlay {
            return n.max(1);
        }
        if self.network == Network::Regtest {
            150
        } else {
            210_000
        }
    }

    /// Override the network subsidy halving interval.
    pub fn overlay_subsidy_halving_interval(&mut self, interval: u32) {
        self.subsidy_halving_overlay = Some(interval.max(1));
    }

    /// Coinbase maturity in blocks (Core default).
    pub fn coinbase_maturity(&self) -> u32 {
        100
    }

    /// BIP34 coinbase-height push required at this height?
    #[inline]
    pub fn bip34_active_at(&self, height: u32) -> bool {
        height >= self.btc.bip34_height
    }

    /// Core skips BIP30 only when this block is above BIP34 height, below
    /// [`BIP34_IMPLIES_BIP30_LIMIT`], and the header at BIP34 height is
    /// [`Self::bip34_hash`].
    #[inline]
    pub fn bip30_skipped_for_bip34_ancestry(
        &self,
        height: u32,
        ancestor_at_bip34: Option<BlockHash>,
    ) -> bool {
        if height >= BIP34_IMPLIES_BIP30_LIMIT {
            return false;
        }
        let Some(expect) = self.bip34_hash else {
            return false;
        };
        if height <= self.btc.bip34_height {
            return false;
        }
        ancestor_at_bip34 == Some(expect)
    }

    /// Core `IsBIP30Repeat`: the two mainnet blocks that overwrite an earlier
    /// **unspent** coinbase (not the spent-duplicate rule).
    ///
    /// `d5d27987…` at 91812 is overwritten by 91842 (30 blocks later — still
    /// immature). `e3bf3d07…` at 91722 is overwritten by 91880. Core skips
    /// BIP30 for those two **hashes** so IBD can pass. Every other pre-BIP34
    /// overwrite of an unspent sibling is still `bad-txns-BIP30`.
    #[inline]
    pub fn is_bip30_repeat(&self, height: u32, block_hash: BlockHash) -> bool {
        if self.network != Network::Bitcoin {
            return false;
        }
        match height {
            91842 => {
                block_hash
                    == block_hash_from_display_hex(
                        "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec",
                    )
            }
            91880 => {
                block_hash
                    == block_hash_from_display_hex(
                        "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721",
                    )
            }
            _ => false,
        }
    }

    #[inline]
    pub fn bip65_active_at(&self, height: u32) -> bool {
        height >= self.btc.bip65_height
    }

    /// BIP66 strict DER encoding required?
    #[inline]
    pub fn bip66_active_at(&self, height: u32) -> bool {
        height >= self.btc.bip66_height
    }

    /// BIP112 CHECKSEQUENCEVERIFY active?
    ///
    /// Buried heights match Bitcoin Core `CMainParams` / `SigNetParams` and
    /// Bitcoin Inquisition (same buried CSV on mainnet/signet):
    /// mainnet 419328, testnet3 770112, signet/testnet4 1, regtest 1.
    #[inline]
    pub fn csv_active_at(&self, height: u32) -> bool {
        height >= self.csv_height()
    }

    /// Buried height for BIP68/112/113 (CSV package).
    pub fn csv_height(&self) -> u32 {
        if let Some(h) = self.csv_height_overlay {
            return h;
        }
        match self.network {
            Network::Bitcoin => 419_328,
            Network::Testnet => 770_112,
            Network::Signet | Network::Testnet4 => 1,
            // Core regtest historically 432; we use 1 (always-on for local mining).
            Network::Regtest => 1,
        }
    }

    /// BIP141/143/147 segwit consensus active?
    ///
    /// Core + Inquisition: mainnet 481824, testnet3 834624, signet 1, regtest 0
    /// (always). Signet BIP325 blocks carry witness from height 1 — archive prep
    /// must not apply this gate with a fake height 0 (see `ValidationContext`).
    #[inline]
    pub fn segwit_active_at(&self, height: u32) -> bool {
        height >= self.segwit_height()
    }

    pub fn segwit_height(&self) -> u32 {
        if let Some(h) = self.segwit_height_overlay {
            return h;
        }
        match self.network {
            Network::Bitcoin => 481_824,
            Network::Testnet => 834_624,
            Network::Signet | Network::Testnet4 => 1,
            Network::Regtest => 0,
        }
    }

    /// Core `-testactivationheight=name@height` (regtest only).
    ///
    /// Names match Core v31.1 `GetBuriedDeployment`: `segwit`, `bip34`,
    /// `dersig`, `cltv`, `csv`. Confirm / script jobs read these getters.
    pub fn apply_test_activation_height(
        &mut self,
        name: &str,
        height: u32,
    ) -> Result<(), &'static str> {
        if self.network != Network::Regtest {
            return Err("testactivationheight is regtest only");
        }
        match name {
            "bip34" => self.btc.bip34_height = height,
            "dersig" => self.btc.bip66_height = height,
            "cltv" => self.btc.bip65_height = height,
            "csv" => self.csv_height_overlay = Some(height),
            "segwit" => self.segwit_height_overlay = Some(height),
            _ => return Err("invalid testactivationheight name"),
        }
        Ok(())
    }

    /// Parse one Core `name@height` token.
    pub fn parse_test_activation_height(spec: &str) -> Result<(&str, u32), &'static str> {
        let (name, rest) = spec.split_once('@').ok_or("invalid format (name@height)")?;
        if name.is_empty() {
            return Err("invalid format (name@height)");
        }
        let height: u32 = rest.parse().map_err(|_| "invalid height")?;
        Ok((name, height))
    }

    /// BIP341/342 taproot active?
    ///
    /// Core mainnet buried 709632 (Inquisition same). Signet/testnet4: 1.
    /// Testnet3: ~2011968 (Inquisition `TaprootHeight`; Core may still use
    /// versionbits — we pin buried for script flags).
    #[inline]
    pub fn taproot_active_at(&self, height: u32) -> bool {
        height >= self.taproot_height()
    }

    pub fn taproot_height(&self) -> u32 {
        match self.network {
            Network::Bitcoin => 709_632,
            Network::Testnet => 2_011_968,
            Network::Signet | Network::Testnet4 => 1,
            Network::Regtest => 0,
        }
    }

    /// `OP_CAT` at `height`.
    ///
    /// Default signet uses the Inquisition buried height. Regtest enables
    /// the opcode at every height. Every other network, including a custom
    /// signet, is off.
    #[inline]
    pub fn heretical_at(&self, height: u32) -> crate::heretical::HereticalFlags {
        crate::heretical::flags_at(self, height)
    }
}

#[doc(hidden)]
pub fn block_hash_from_display_hex(hex: &str) -> BlockHash {
    hex.parse().expect("block hash hex")
}

/// Mainnet assumeutxo block at height 840_000 (Core `kernel/chainparams.cpp`,
/// display order). The default milestone hash, not Core's later assumevalid.
pub const MAINNET_MILESTONE_HASH: &str =
    "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5";

/// Core mainnet `nMinimumChainWork` (display hex, big-endian). Refresh at release.
pub const MAINNET_MIN_CHAIN_WORK: &str =
    "000000000000000000000000000000000000000145ec036acc5ba740052af1a0";

/// Testnet3 assumeutxo block at height 2_500_000 (Core `kernel/chainparams.cpp`,
/// display order). Same role as [`MAINNET_MILESTONE_HASH`].
pub const TESTNET_MILESTONE_HASH: &str =
    "0000000000000093bcb68c03a9a168ae252572d348a2eaeba2cdf9231d73206f";

/// Core testnet3 `nMinimumChainWork` (display hex, big-endian).
pub const TESTNET_MIN_CHAIN_WORK: &str =
    "0000000000000000000000000000000000000000000017f49f702147f10c0eb6";

/// Default IBD milestone height. `0` means full script validation.
///
/// Signet is 0 on purpose: signet IBD runs every script (slower than a
/// height skip; that is the dress rehearsal). Mainnet (840_000) and testnet3
/// (2_500_000) defaults are paired with [`default_milestone_anchor`].
/// Operators still override with `--milestone HEIGHT` (height-only) or
/// `--milestone 0`.
pub fn default_milestone_height(network: rbitcoin_primitives::Network) -> u32 {
    match network {
        rbitcoin_primitives::Network::Mainnet => 840_000,
        rbitcoin_primitives::Network::Testnet => 2_500_000,
        rbitcoin_primitives::Network::Signet => 0,
        rbitcoin_primitives::Network::Regtest => 0,
    }
}

/// Anchor for the default milestone (block hash at the default height plus
/// Core `nMinimumChainWork`). `None` where the default is 0.
pub fn default_milestone_anchor(
    network: rbitcoin_primitives::Network,
) -> Option<crate::milestone::MilestoneAnchor> {
    let hash = match network {
        rbitcoin_primitives::Network::Mainnet => MAINNET_MILESTONE_HASH,
        rbitcoin_primitives::Network::Testnet => TESTNET_MILESTONE_HASH,
        rbitcoin_primitives::Network::Signet | rbitcoin_primitives::Network::Regtest => {
            return None
        }
    };
    Some(crate::milestone::MilestoneAnchor {
        hash: block_hash_from_display_hex(hash),
        min_work_be: default_min_chain_work_be(network)?,
    })
}

/// Core `nMinimumChainWork` as 32 big-endian bytes, where we ship one.
pub fn default_min_chain_work_be(network: rbitcoin_primitives::Network) -> Option<[u8; 32]> {
    match network {
        rbitcoin_primitives::Network::Mainnet => {
            Some(min_work_from_display_hex(MAINNET_MIN_CHAIN_WORK))
        }
        rbitcoin_primitives::Network::Testnet => {
            Some(min_work_from_display_hex(TESTNET_MIN_CHAIN_WORK))
        }
        rbitcoin_primitives::Network::Signet | rbitcoin_primitives::Network::Regtest => None,
    }
}

#[doc(hidden)]
pub fn min_work_from_display_hex(hex: &str) -> [u8; 32] {
    rbitcoin_primitives::hex_decode(hex)
        .expect("min chain work hex")
        .try_into()
        .expect("min chain work hex")
}

/// Verify height-0 block hash matches params genesis.
pub fn check_genesis_hash(params: &ChainParams, hash: BlockHash) -> bool {
    hash == params.genesis_hash
}

pub fn genesis_block(params: &ChainParams) -> bitcoin::block::Block {
    constants::genesis_block(params.network)
}
