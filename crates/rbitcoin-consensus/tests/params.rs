use bitcoin::script::ScriptBuf;
use rbitcoin_consensus::params::*;

/// Core `SigNetParams` / Inquisition signet: soft forks at height 1 (not 0).
#[test]
fn signet_buried_deployments_match_core() {
    let p = ChainParams::signet();
    assert_eq!(p.btc.bip34_height, 1);
    assert_eq!(p.btc.bip65_height, 1);
    assert_eq!(p.btc.bip66_height, 1);
    assert_eq!(p.csv_height(), 1);
    assert_eq!(p.segwit_height(), 1);
    assert_eq!(p.taproot_height(), 1);
    assert!(!p.segwit_active_at(0));
    assert!(p.segwit_active_at(1));
    assert!(p.signet_challenge.is_some());
    assert_eq!(p.btc.pow_target_spacing, 10 * 60);
}

#[test]
fn custom_signet_uses_challenge_and_block_time() {
    let challenge = ScriptBuf::from_bytes(vec![0x51]);
    let p = ChainParams::custom_signet(challenge.clone(), 60).unwrap();

    assert_eq!(p.signet_challenge.as_ref(), Some(&challenge));
    assert_eq!(p.btc.pow_target_spacing, 60);
    assert_eq!(p.btc.pow_target_timespan, 14 * 24 * 60 * 60);
    assert_eq!(p.difficulty_adjustment_interval(), 20_160);
    assert!(ChainParams::custom_signet(challenge, 0).is_err());
}

#[test]
fn bip34_hash_gates_bip30_like_core() {
    let main = ChainParams::mainnet();
    assert_eq!(main.btc.bip34_height, 227_931);
    let hash = main.bip34_hash.expect("mainnet BIP34 hash");
    // Core chainparams `consensus.BIP34Hash` (block 227931). A look-alike
    // that is not this header keeps BIP30 on for the whole mainnet IBD.
    assert_eq!(
        hash,
        block_hash_from_display_hex(
            "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8",
        )
    );
    assert!(main.bip30_skipped_for_bip34_ancestry(227_932, Some(hash)));
    assert!(!main.bip30_skipped_for_bip34_ancestry(227_931, Some(hash)));
    assert!(!main.bip30_skipped_for_bip34_ancestry(BIP34_IMPLIES_BIP30_LIMIT, Some(hash)));
    assert!(!main.bip30_skipped_for_bip34_ancestry(227_932, None));
    let tn = ChainParams::testnet();
    assert_eq!(tn.btc.bip34_height, 21_111);
    assert_eq!(
        tn.bip34_hash.expect("testnet BIP34 hash"),
        block_hash_from_display_hex(
            "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8",
        )
    );
    assert!(ChainParams::signet().bip34_hash.is_none());
    assert!(ChainParams::regtest().bip34_hash.is_none());
    assert_eq!(ChainParams::regtest().btc.bip34_height, 1);
    assert!(!ChainParams::regtest().bip30_skipped_for_bip34_ancestry(2, None));
    assert!(!ChainParams::signet().bip30_skipped_for_bip34_ancestry(2, None));
}

/// Core `IsBIP30Repeat` — height+hash, mainnet only.
#[test]
fn is_bip30_repeat_matches_core() {
    let main = ChainParams::mainnet();
    let h91842 = block_hash_from_display_hex(
        "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec",
    );
    let h91880 = block_hash_from_display_hex(
        "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721",
    );
    assert!(main.is_bip30_repeat(91842, h91842));
    assert!(main.is_bip30_repeat(91880, h91880));
    assert!(
        !main.is_bip30_repeat(91842, h91880),
        "wrong hash at 91842 is not grandfathered"
    );
    assert!(!main.is_bip30_repeat(91880, h91842));
    assert!(
        !main.is_bip30_repeat(91859, h91842),
        "batch-first height 91859 is not an exception"
    );
    assert!(!ChainParams::regtest().is_bip30_repeat(91880, h91880));
    assert!(main.bip30_exception_height(91_842));
    assert!(main.bip30_exception_height(91_880));
    assert!(!main.bip30_exception_height(91_859));
    assert!(!ChainParams::signet().bip30_exception_height(91_842));
}

#[test]
fn mainnet_min_chain_work_is_core_n_minimum_chain_work() {
    let work = default_min_chain_work_be(rbitcoin_primitives::Network::Mainnet).unwrap();
    assert_eq!(work, min_work_from_display_hex(MAINNET_MIN_CHAIN_WORK));
    assert!(
        work.iter().any(|b| *b != 0),
        "minimum chain work must not be zero"
    );
}

/// Mainnet buried heights (Core + Inquisition).
#[test]
fn mainnet_buried_deployments_match_core() {
    let p = ChainParams::mainnet();
    assert_eq!(p.btc.bip34_height, 227_931);
    assert_eq!(p.csv_height(), 419_328);
    assert_eq!(p.segwit_height(), 481_824);
    assert_eq!(p.taproot_height(), 709_632);
    assert!(!p.segwit_active_at(481_823));
    assert!(p.segwit_active_at(481_824));
}

#[test]
fn for_network_and_helpers() {
    use rbitcoin_primitives::Network;
    assert_eq!(
        ChainParams::for_network(Network::Mainnet).network,
        bitcoin::Network::Bitcoin
    );
    assert_eq!(
        ChainParams::for_network(Network::Testnet).network,
        bitcoin::Network::Testnet
    );
    assert_eq!(
        ChainParams::for_network(Network::Signet).network,
        bitcoin::Network::Signet
    );
    assert_eq!(
        ChainParams::for_network(Network::Regtest).network,
        bitcoin::Network::Regtest
    );

    let tn = ChainParams::testnet();
    assert_eq!(tn.csv_height(), 770_112);
    assert_eq!(tn.segwit_height(), 834_624);
    assert_eq!(tn.taproot_height(), 2_011_968);
    assert_eq!(tn.coinbase_maturity(), 100);
    assert!(!tn.no_pow_retargeting());
    assert!(tn.allow_min_difficulty_blocks());
    assert!(tn.difficulty_adjustment_interval() > 0);
    assert!(tn.bip34_active_at(tn.btc.bip34_height));
    assert!(tn.bip65_active_at(tn.btc.bip65_height));
    assert!(tn.bip66_active_at(tn.btc.bip66_height));
    assert!(tn.csv_active_at(tn.csv_height()));
    assert!(tn.taproot_active_at(tn.taproot_height()));
    assert!(check_genesis_hash(&tn, tn.genesis_hash));
    let g = genesis_block(&tn);
    assert_eq!(g.block_hash(), tn.genesis_hash);

    let rt = ChainParams::regtest();
    assert!(rt.no_pow_retargeting() || rt.difficulty_adjustment_interval() > 0);
    assert_eq!(rt.btc.bip65_height, 1);
    assert_eq!(rt.btc.bip66_height, 1);
    assert!(rt.bip65_active_at(1));
    assert!(rt.bip66_active_at(1));
}

/// Core `-testactivationheight=csv@102` (regtest) must move the buried height.
#[test]
fn testactivationheight_csv_overlay() {
    let mut p = ChainParams::regtest();
    assert_eq!(p.csv_height(), 1);
    p.apply_test_activation_height("csv", 102).unwrap();
    assert_eq!(p.csv_height(), 102);
    assert!(!p.csv_active_at(101));
    assert!(p.csv_active_at(102));
    p.apply_test_activation_height("dersig", 50).unwrap();
    assert_eq!(p.btc.bip66_height, 50);
    assert!(p.apply_test_activation_height("notadeployment", 1).is_err());
    let mut main = ChainParams::mainnet();
    assert!(main.apply_test_activation_height("csv", 102).is_err());
}

#[test]
fn regtest_pow_bits_overlay_is_regtest_only_and_bounded() {
    let limit = 0x207f_ffff;
    let mut p = ChainParams::regtest();
    assert_eq!(p.regtest_pow_bits_overlay, None);
    p.apply_regtest_pow_bits(0x200f_ffff).unwrap();
    assert_eq!(
        p.regtest_pow_bits_overlay,
        Some(bitcoin::CompactTarget::from_consensus(0x200f_ffff))
    );
    for bits in [
        limit,       // the pow limit itself is a no-op
        0x2100_ffff, // easier than the limit
        0x207f_ffff + 1,
        0x0000_0000, // zero mantissa
        0x0300_0000,
        0x0100_3456, // shifts to a zero target
        0x2080_0001, // negative
        0x0280_0002, // negative, low bit clear
        0x2300_0001, // overflow
    ] {
        let mut p = ChainParams::regtest();
        assert!(p.apply_regtest_pow_bits(bits).is_err(), "{bits:#x}");
        assert_eq!(p.regtest_pow_bits_overlay, None);
    }
    for mut other in [
        ChainParams::mainnet(),
        ChainParams::testnet(),
        ChainParams::signet(),
    ] {
        assert!(other.apply_regtest_pow_bits(0x1d00_ffff).is_err());
        assert_eq!(other.regtest_pow_bits_overlay, None);
    }

    assert_eq!(
        ChainParams::parse_regtest_pow_bits("0x1f7fffff"),
        Ok(0x1f7f_ffff)
    );
    assert_eq!(
        ChainParams::parse_regtest_pow_bits("1F7fffff"),
        Ok(0x1f7f_ffff)
    );
    for bad in ["", "0x", "zz", "0x123456789", "-1"] {
        assert!(ChainParams::parse_regtest_pow_bits(bad).is_err(), "{bad}");
    }
}
