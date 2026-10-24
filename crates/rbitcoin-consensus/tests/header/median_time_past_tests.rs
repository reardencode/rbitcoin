use bitcoin::block::Version;
use bitcoin::hashes::Hash;
use bitcoin::{CompactTarget, Target};
use rbitcoin_consensus::error::ConsensusError;
use rbitcoin_consensus::header::*;
use rbitcoin_consensus::params::ChainParams;
use rbitcoin_primitives::Height;

fn difficulty_float(bits: u32) -> f64 {
    Target::from_compact(CompactTarget::from_consensus(bits)).difficulty_float()
}

#[test]
fn max_target_bits_are_difficulty_one() {
    assert_eq!(difficulty_float(0x1d00_ffff), 1.0);
}

/// Block 32256 `nBits` (`0x1d00d86a`), the compact pinned by
/// `mainnet_retarget_32256_matches_core_compact`.
#[test]
fn mainnet_32256_difficulty_is_frozen() {
    assert_eq!(difficulty_float(0x1d00_d86a), 1.1828995343128408);
}

#[test]
fn pow_hash_meets_target_meet_miss_and_limit() {
    let rt = ChainParams::regtest();
    let easy = CompactTarget::from_consensus(0x207f_ffff);
    pow_hash_meets_target([0u8; 32], easy, rt.pow_limit).unwrap();
    let mainnet_bits = CompactTarget::from_consensus(0x1d00_ffff);
    let miss = pow_hash_meets_target([0xff; 32], mainnet_bits, Target::MAX_ATTAINABLE_MAINNET)
        .unwrap_err();
    assert!(matches!(miss, ConsensusError::InvalidPow), "{miss:?}");
    let err = pow_hash_meets_target([0u8; 32], easy, ChainParams::mainnet().pow_limit).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadHeader(s) if s.contains("pow limit")),
        "{err:?}"
    );
}

/// Mainnet block 32256 (`000000004f2886a170adb7204cb0c7a824217dd24d11a74423d564c4e0904967`).
///
/// Parent 32255 time `1262152739`, bits `0x1d00ffff`. Period start is
/// height 30240, time `1261130161`. Timespan `1022578` is inside the
/// clamp, so the compact is Core's `GetCompact` of that product:
/// `0x1d00d86a`. The literal is not produced by calling the function
/// under test.
#[test]
fn mainnet_retarget_32256_matches_core_compact() {
    let params = ChainParams::mainnet();
    let got = next_work_bits(
        &params,
        32_256,
        CompactTarget::from_consensus(0x1d00_ffff),
        1_262_152_739,
        1_262_152_739,
        Some(1_261_130_161),
        |_| None,
    );
    assert_eq!(got, Some(CompactTarget::from_consensus(0x1d00_d86a)));
}

/// Clamp and pow-limit cap, with expected compacts written as integers.
///
/// Core order: timespan clamped to `[target/4, target*4]` (1_209_600 is
/// two weeks), `target * timespan / 1_209_600`, then cap at the pow
/// limit, then `GetCompact`.
///
/// - Quarter floor from `0x1d00ffff` and a 1-second span. Clamped span is
///   302_400. `0xffff << 208` * 302_400 / 1_209_600 compacts to
///   `0x1c3fffc0`. Without the floor the compact is `0x1a0ddead`.
/// - 4× ceiling from `0x1c1fffe0` (`0xffff << 205`) and a span one second
///   past four periods. Clamped product compacts to `0x1c7fff80`, still
///   under the pow limit. Without the ceiling the compact is `0x1c7fff81`.
/// - Pow-limit cap from `0x1d007fff` (`0x7fff << 208`) and an exact 4×
///   span. The product exceeds the limit. Compact is `0x1d00ffff`.
///   Without the cap it is `0x1d01fffc`.
#[test]
fn retarget_clamps_timespan_and_caps_at_pow_limit() {
    let params = ChainParams::mainnet();
    let bits = |prev: u32, prev_time: u32, first: u32| {
        next_work_bits(
            &params,
            2_016,
            CompactTarget::from_consensus(prev),
            prev_time,
            prev_time,
            Some(first),
            |_| None,
        )
    };
    assert_eq!(
        bits(0x1d00_ffff, 2, 1),
        Some(CompactTarget::from_consensus(0x1c3f_ffc0))
    );
    assert_eq!(
        bits(0x1c1f_ffe0, 4_838_402, 1),
        Some(CompactTarget::from_consensus(0x1c7f_ff80))
    );
    assert_eq!(
        bits(0x1d00_7fff, 4_838_401, 1),
        Some(CompactTarget::from_consensus(0x1d00_ffff))
    );
}

#[test]
fn mtp_times_picks_middle_of_sorted() {
    assert_eq!(
        median_time_past_times(MedianWindow::new(&[3, 1, 2]).unwrap()),
        2
    );
    assert_eq!(
        median_time_past_times(MedianWindow::new(&[10]).unwrap()),
        10
    );
    // Even length: Core takes sorted[len/2] (upper middle).
    assert_eq!(
        median_time_past_times(MedianWindow::new(&[1, 2, 3, 4]).unwrap()),
        3
    );
}

#[test]
fn next_work_bits_walks_back_past_min_difficulty() {
    let params = ChainParams::testnet();
    let limit = params.pow_limit.to_compact_lossy();
    let full = CompactTarget::from_consensus(0x1d00_eeee);
    assert_ne!(full, limit);
    let prev_time = 1_000_000u32;
    let walked = next_work_bits(
        &params,
        3,
        limit,
        prev_time,
        prev_time + 100,
        None,
        |h| match h {
            1 => Some(limit),
            0 => Some(full),
            _ => None,
        },
    )
    .unwrap();
    assert_eq!(walked, full);

    let spacing = params.btc.pow_target_spacing;
    let gap = next_work_bits(
        &params,
        3,
        full,
        prev_time,
        prev_time + (spacing as u32) * 2 + 1,
        None,
        |_| None,
    )
    .unwrap();
    assert_eq!(gap, limit);

    let mainnet = ChainParams::mainnet();
    let kept = next_work_bits(
        &mainnet,
        3,
        full,
        prev_time,
        prev_time + (spacing as u32) * 2 + 1,
        None,
        |_| Some(limit),
    )
    .unwrap();
    assert_eq!(kept, full);
}

#[test]
fn check_header_rejects_without_a_store() {
    let params = ChainParams::mainnet();
    let genesis = rbitcoin_consensus::params::genesis_block(&params);
    let mut bad = genesis.header;
    bad.nonce = bad.nonce.wrapping_add(1);
    let err = check_header(
        &params,
        Height(0),
        &bad,
        bad.block_hash().to_byte_array(),
        None,
        &[],
        None,
        |_| None,
    )
    .unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadHeader(s) if s.contains("genesis")),
        "{err:?}"
    );

    let parent = ParentHeader {
        hash: [1u8; 32],
        time: genesis.header.time,
        bits: genesis.header.bits,
    };
    let mut child = genesis.header;
    child.time = parent.time + 1;
    let missing = check_header(
        &params,
        Height(1),
        &child,
        [0xff; 32],
        None,
        &[parent.time],
        None,
        |_| None,
    )
    .unwrap_err();
    assert!(matches!(missing, ConsensusError::BadPrev), "{missing:?}");

    child.prev_blockhash = bitcoin::BlockHash::from_byte_array([2u8; 32]);
    let bad_prev = check_header(
        &params,
        Height(1),
        &child,
        [0xff; 32],
        Some(parent),
        &[parent.time],
        None,
        |_| None,
    )
    .unwrap_err();
    assert!(matches!(bad_prev, ConsensusError::BadPrev), "{bad_prev:?}");

    child.prev_blockhash = bitcoin::BlockHash::from_byte_array(parent.hash);
    child.time = parent.time;
    let mtp = check_header(
        &params,
        Height(1),
        &child,
        [0xff; 32],
        Some(parent),
        &[parent.time],
        None,
        |_| None,
    )
    .unwrap_err();
    assert!(
        matches!(mtp, ConsensusError::BadHeader(s) if s.contains("median-time-past")),
        "{mtp:?}"
    );

    child.time = parent.time + 1;
    child.bits = CompactTarget::from_consensus(0x1d00_eeee);
    let bits = check_header(
        &params,
        Height(1),
        &child,
        [0xff; 32],
        Some(parent),
        &[parent.time],
        None,
        |_| None,
    )
    .unwrap_err();
    assert!(
        matches!(bits, ConsensusError::BadHeader(s) if s.contains("proof of work bits")),
        "{bits:?}"
    );

    child.bits = parent.bits;
    let pow = check_header(
        &params,
        Height(1),
        &child,
        [0xff; 32],
        Some(parent),
        &[parent.time],
        None,
        |_| None,
    )
    .unwrap_err();
    assert!(matches!(pow, ConsensusError::InvalidPow), "{pow:?}");

    let interval = params.difficulty_adjustment_interval();
    let retarget = check_header(
        &params,
        Height(interval),
        &child,
        [0xff; 32],
        Some(parent),
        &[parent.time],
        None,
        |_| Some(parent.bits),
    )
    .unwrap_err();
    assert!(
        matches!(retarget, ConsensusError::BadHeader(s) if s.contains("missing retarget")),
        "{retarget:?}"
    );
}

#[test]
fn check_header_returns_the_median_it_checked() {
    let params = ChainParams::regtest();
    let genesis = rbitcoin_consensus::params::genesis_block(&params);
    let genesis_mtp = check_header(
        &params,
        Height(0),
        &genesis.header,
        genesis.block_hash().to_byte_array(),
        None,
        &[],
        None,
        |_| None,
    )
    .unwrap();
    assert_eq!(genesis_mtp, 0);

    let parent_time = genesis.header.time;
    let block = rbitcoin_consensus::regtest_pad::mine_empty_regtest(
        genesis.block_hash(),
        parent_time + 1,
        1,
    );
    let times = [parent_time, parent_time - 1, parent_time + 2];
    let mtp = check_header(
        &params,
        Height(1),
        &block.header,
        block.block_hash().to_byte_array(),
        Some(ParentHeader {
            hash: genesis.block_hash().to_byte_array(),
            time: parent_time,
            bits: genesis.header.bits,
        }),
        &times,
        None,
        |_| None,
    )
    .unwrap();
    assert_eq!(
        mtp,
        median_time_past_times(MedianWindow::new(&times).unwrap())
    );
    assert_eq!(mtp, parent_time);
}

/// A waived median check still returns the window. `0` would make a later
/// locktime look non-final.
#[test]
fn waived_median_keeps_the_window() {
    let params = ChainParams::regtest();
    let genesis = rbitcoin_consensus::params::genesis_block(&params);
    let parent_time = genesis.header.time;
    let mut block = rbitcoin_consensus::regtest_pad::mine_empty_regtest(
        genesis.block_hash(),
        parent_time + 1,
        1,
    );
    block.header.time = parent_time;
    // The timestamp is in the header hash. Meet the target again so the only
    // fault under the collector is the median comparison.
    for _ in 0..10_000 {
        if block.header.validate_pow(block.header.target()).is_ok() {
            break;
        }
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    assert!(
        block.header.validate_pow(block.header.target()).is_ok(),
        "fixture must meet proof-of-work"
    );
    let _guard = rbitcoin_consensus::TrustCollect::enter();
    let mtp = check_header(
        &params,
        Height(1),
        &block.header,
        block.block_hash().to_byte_array(),
        Some(ParentHeader {
            hash: genesis.block_hash().to_byte_array(),
            time: parent_time,
            bits: genesis.header.bits,
        }),
        &[parent_time],
        None,
        |_| None,
    )
    .expect("waived median still returns");
    assert_eq!(mtp, parent_time);
    let warns = rbitcoin_consensus::drain_warnings();
    assert!(
        warns.iter().any(|(_, e)| matches!(
            e,
            ConsensusError::BadHeader(s) if *s == "timestamp <= median-time-past"
        )),
        "{warns:?}"
    );
}

#[test]
fn check_header_version_and_future_time_regtest() {
    let params = ChainParams::regtest();
    let mut h = rbitcoin_consensus::params::genesis_block(&params).header;
    h.version = Version::from_consensus(1);
    rbitcoin_consensus::clock::with_now(1_700_000_000, || {
        h.time = 1_700_000_000;
        let err = check_header_version_and_future_time(&params, Height(1), &h).unwrap_err();
        assert!(matches!(err, ConsensusError::BadVersion(1)), "{err:?}");
        h.version = Version::from_consensus(4);
        h.time = 1_700_000_000 + 3 * 60 * 60;
        let err = check_header_version_and_future_time(&params, Height(1), &h).unwrap_err();
        assert!(
            matches!(err, ConsensusError::BadHeader(s) if s.contains("future")),
            "{err:?}"
        );
        h.time = 1_700_000_000 + 60 * 60;
        check_header_version_and_future_time(&params, Height(1), &h).unwrap();
    });
}

#[test]
fn h8_timestamp_exactly_two_hours_accepts_plus_one_rejects() {
    let params = ChainParams::regtest();
    let mut h = rbitcoin_consensus::params::genesis_block(&params).header;
    h.version = Version::from_consensus(4);
    rbitcoin_consensus::clock::with_now(1_700_000_000, || {
        h.time = 1_700_000_000 + 2 * 60 * 60;
        check_header_version_and_future_time(&params, Height(1), &h).unwrap();
        h.time = 1_700_000_000 + 2 * 60 * 60 + 1;
        let err = check_header_version_and_future_time(&params, Height(1), &h).unwrap_err();
        assert!(
            matches!(err, ConsensusError::BadHeader(s) if s.contains("future")),
            "{err:?}"
        );
    });
}

#[test]
fn h9_version_floors_at_bip34_66_65() {
    let rt = ChainParams::regtest();
    let mut h = rbitcoin_consensus::params::genesis_block(&rt).header;
    rbitcoin_consensus::clock::with_now(1_700_000_000, || {
        h.time = 1_700_000_000;
        h.version = Version::from_consensus(3);
        let err = check_header_version_and_future_time(&rt, Height(1), &h).unwrap_err();
        assert!(matches!(err, ConsensusError::BadVersion(3)), "{err:?}");
        h.version = Version::from_consensus(4);
        check_header_version_and_future_time(&rt, Height(1), &h).unwrap();
    });

    let main = ChainParams::mainnet();
    let mut mh = rbitcoin_consensus::params::genesis_block(&main).header;
    rbitcoin_consensus::clock::with_now(1_700_000_000, || {
        mh.time = 1_700_000_000;
        let bip34 = main.btc.bip34_height;
        mh.version = Version::from_consensus(1);
        check_header_version_and_future_time(&main, Height(bip34 - 1), &mh).unwrap();
        let err = check_header_version_and_future_time(&main, Height(bip34), &mh).unwrap_err();
        assert!(matches!(err, ConsensusError::BadVersion(1)), "{err:?}");
        mh.version = Version::from_consensus(2);
        check_header_version_and_future_time(&main, Height(bip34), &mh).unwrap();

        let bip66 = main.btc.bip66_height;
        mh.version = Version::from_consensus(2);
        let err = check_header_version_and_future_time(&main, Height(bip66), &mh).unwrap_err();
        assert!(matches!(err, ConsensusError::BadVersion(2)), "{err:?}");
        mh.version = Version::from_consensus(3);
        check_header_version_and_future_time(&main, Height(bip66), &mh).unwrap();

        let bip65 = main.btc.bip65_height;
        mh.version = Version::from_consensus(3);
        let err = check_header_version_and_future_time(&main, Height(bip65), &mh).unwrap_err();
        assert!(matches!(err, ConsensusError::BadVersion(3)), "{err:?}");
        mh.version = Version::from_consensus(4);
        check_header_version_and_future_time(&main, Height(bip65), &mh).unwrap();
    });
}
