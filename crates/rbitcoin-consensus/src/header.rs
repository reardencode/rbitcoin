use crate::error::ConsensusError;
use crate::params::{check_genesis_hash, ChainParams};
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::{CompactTarget, Target};
pub use rbitcoin_primitives::median_time_past_times;
use rbitcoin_primitives::Height;

/// Parent header facts for [`check_header`]. Copied so a height above zero can
/// use the same parent for linkage and for the work calculation.
#[derive(Clone, Copy)]
pub struct ParentHeader {
    pub hash: [u8; 32],
    pub time: u32,
    pub bits: CompactTarget,
}

/// Header rules from the header bytes plus caller facts. No datadir.
///
/// `mtp_times` ends at the parent (up to 11 timestamps). `period_first_time`
/// is the header `interval` blocks before a retarget height. `bits_at` supplies
/// earlier `nBits` for the testnet min-difficulty walk.
///
/// On success the value is that parent median, sorted once. Genesis has no
/// parent window and returns `0`.
#[allow(clippy::too_many_arguments)] // each argument is one caller fact
                                     // btc-lean: BLK-040 BLK-041 INV-098
pub fn check_header(
    params: &ChainParams,
    height: Height,
    header: &Header,
    hash: [u8; 32],
    parent: Option<ParentHeader>,
    mtp_times: &[u32],
    period_first_time: Option<u32>,
    mut bits_at: impl FnMut(u32) -> Option<CompactTarget>,
) -> Result<u32, ConsensusError> {
    let hash_bh = bitcoin::BlockHash::from_byte_array(hash);
    if height.0 == 0 {
        if !check_genesis_hash(params, hash_bh) {
            return Err(ConsensusError::BadHeader("genesis hash mismatch"));
        }
        let expected = crate::params::genesis_block(params).header.bits;
        if header.bits != expected {
            return Err(ConsensusError::BadHeader("incorrect proof of work bits"));
        }
        pow_hash_meets_target(hash, header.bits, params.pow_limit)?;
        return Ok(0);
    }

    let parent = parent.ok_or(ConsensusError::BadPrev)?;
    if parent.hash != header.prev_blockhash.to_byte_array() {
        return Err(ConsensusError::BadPrev);
    }
    let mtp = median_time_past_times(mtp_times)
        .map_err(|_| ConsensusError::BadHeader("empty median time"))?;
    // btc-lean: BLK-057 INV-099
    if header.time <= mtp {
        return Err(ConsensusError::BadHeader("timestamp <= median-time-past"));
    }
    check_header_version_and_future_time(params, height, header)?;

    let interval = params.difficulty_adjustment_interval();
    if interval > 0
        && height.0.is_multiple_of(interval)
        && !params.no_pow_retargeting()
        && period_first_time.is_none()
    {
        return Err(ConsensusError::BadHeader("missing retarget first header"));
    }
    let expected = next_work_bits(
        params,
        height.0,
        parent.bits,
        parent.time,
        header.time,
        period_first_time,
        &mut bits_at,
    )
    .ok_or(ConsensusError::BadPrev)?;
    if header.bits != expected {
        return Err(ConsensusError::BadHeader("incorrect proof of work bits"));
    }
    pow_hash_meets_target(hash, header.bits, params.pow_limit)?;
    Ok(mtp)
}

/// Validate header linkage, MTP, difficulty bits, and proof-of-work.
pub fn validate_header_on_parent(
    params: &ChainParams,
    height: Height,
    header: &Header,
    parent_mtp: u32,
    expected_bits: CompactTarget,
) -> Result<(), ConsensusError> {
    if header.time <= parent_mtp {
        return Err(ConsensusError::BadHeader("timestamp <= median-time-past"));
    }
    check_header_version_and_future_time(params, height, header)?;
    if header.bits != expected_bits {
        return Err(ConsensusError::BadHeader("incorrect proof of work bits"));
    }
    pow_hash_meets_target(
        header.block_hash().to_byte_array(),
        header.bits,
        params.pow_limit,
    )
}

/// POW vs a **caller-computed** header hash (no second SHA256d).
// btc-lean: BLK-003 BLK-039
pub fn pow_hash_meets_target(
    hash: [u8; 32],
    bits: CompactTarget,
    pow_limit: Target,
) -> Result<(), ConsensusError> {
    // btc-lean: BLK-037
    let target = Target::from_compact(bits);
    if target > pow_limit {
        return Err(ConsensusError::BadHeader("target above pow limit"));
    }
    if !target.is_met_by(bitcoin::BlockHash::from_byte_array(hash)) {
        return Err(ConsensusError::InvalidPow);
    }
    Ok(())
}

/// BIP34/66/65 `nVersion` floors and the 2-hour future-time cap (wall clock).
///
/// Core `ContextualCheckBlockHeader`. Assemble uses this instead of a second
/// [`validate_header`] (MTP walk + header rehash).
pub fn check_header_version_and_future_time(
    params: &ChainParams,
    height: Height,
    header: &Header,
) -> Result<(), ConsensusError> {
    const MAX_FUTURE_BLOCK_TIME: u64 = 2 * 60 * 60;
    let now = crate::clock::current_now();
    if u64::from(header.time) > now.saturating_add(MAX_FUTURE_BLOCK_TIME) {
        // btc-lean: BLK-058 INV-101
        return Err(ConsensusError::BadHeader("timestamp too far in future"));
    }
    let ver = header.version.to_consensus();
    if (params.bip34_active_at(height.0) && ver < 2)
        || (params.bip66_active_at(height.0) && ver < 3)
        || (params.bip65_active_at(height.0) && ver < 4)
    {
        // btc-lean: BLK-001 BLK-060 BLK-061 BLK-062 INV-102
        return Err(ConsensusError::BadVersion(ver));
    }
    Ok(())
}

/// Expected `nBits` for the header at `height`, from the parent and the period start.
///
/// `period_first_time` is the timestamp `interval` blocks earlier when `height`
/// is a retarget boundary. `bits_at` supplies earlier `nBits` for the testnet
/// min-difficulty walk. `None` means an ancestor is missing. Median time is
/// [`median_time_past_times`], not this function.
pub fn next_work_bits(
    params: &ChainParams,
    height: u32,
    prev_bits: CompactTarget,
    prev_time: u32,
    header_time: u32,
    period_first_time: Option<u32>,
    mut bits_at: impl FnMut(u32) -> Option<CompactTarget>,
) -> Option<CompactTarget> {
    if height == 0 {
        return None;
    }
    let interval = params.difficulty_adjustment_interval();
    if interval == 0 || !height.is_multiple_of(interval) {
        return min_diff_bits(
            params,
            height,
            prev_bits,
            prev_time,
            header_time,
            &mut bits_at,
        );
    }
    if params.no_pow_retargeting() {
        return Some(prev_bits);
    }
    let first_time = period_first_time?;
    let timespan = u64::from(prev_time.saturating_sub(first_time));
    // btc-lean: BLK-038 BLK-042 BLK-044 BLK-045 BLK-046 BLK-048 BLK-054 INV-094 INV-096 INV-097
    Some(CompactTarget::from_next_work_required(
        prev_bits,
        timespan,
        &params.btc,
    ))
}

// btc-lean: BLK-043 BLK-049 BLK-050 BLK-051 BLK-052 BLK-053 INV-095
fn min_diff_bits(
    params: &ChainParams,
    height: u32,
    prev_bits: CompactTarget,
    prev_time: u32,
    header_time: u32,
    bits_at: &mut impl FnMut(u32) -> Option<CompactTarget>,
) -> Option<CompactTarget> {
    if !params.allow_min_difficulty_blocks() {
        return Some(prev_bits);
    }
    let limit = params.pow_limit.to_compact_lossy();
    let spacing = params.btc.pow_target_spacing;
    if u64::from(header_time) > u64::from(prev_time).saturating_add(spacing.saturating_mul(2)) {
        return Some(limit);
    }
    let interval = params.difficulty_adjustment_interval();
    let mut h = height - 1;
    let mut bits = prev_bits;
    while interval > 0 && !h.is_multiple_of(interval) && bits == limit {
        if h == 0 {
            break;
        }
        h -= 1;
        bits = bits_at(h)?;
    }
    Some(bits)
}

#[cfg(test)]
mod median_time_past_tests {
    use super::*;
    use bitcoin::block::Version;

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
        let err =
            pow_hash_meets_target([0u8; 32], easy, ChainParams::mainnet().pow_limit).unwrap_err();
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
        assert_eq!(median_time_past_times(&[3, 1, 2]).unwrap(), 2);
        assert_eq!(median_time_past_times(&[10]).unwrap(), 10);
        // Even length: Core takes sorted[len/2] (upper middle).
        assert_eq!(median_time_past_times(&[1, 2, 3, 4]).unwrap(), 3);
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
    // btc-lean: BLK-001 BLK-037 BLK-038 BLK-039 BLK-040 BLK-041 BLK-042 BLK-043 BLK-044 BLK-045
    // btc-lean: BLK-046 BLK-048 BLK-049 BLK-050 BLK-051 BLK-052 BLK-053 BLK-054 BLK-056 BLK-057
    // btc-lean: BLK-058 BLK-060 BLK-061 BLK-062 INV-094 INV-095 INV-096 INV-097 INV-098 INV-099
    // btc-lean: INV-101 INV-102
    fn check_header_rejects_without_a_store() {
        let params = ChainParams::mainnet();
        let genesis = crate::params::genesis_block(&params);
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
        let genesis = crate::params::genesis_block(&params);
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
        let block =
            crate::regtest_pad::mine_empty_regtest(genesis.block_hash(), parent_time + 1, 1);
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
        assert_eq!(mtp, median_time_past_times(&times).unwrap());
        assert_eq!(mtp, parent_time);
    }

    #[test]
    fn check_header_version_and_future_time_regtest() {
        let params = ChainParams::regtest();
        let mut h = crate::params::genesis_block(&params).header;
        h.version = Version::from_consensus(1);
        crate::clock::with_now(1_700_000_000, || {
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
    // btc-lean: BLK-130
    fn h8_timestamp_exactly_two_hours_accepts_plus_one_rejects() {
        let params = ChainParams::regtest();
        let mut h = crate::params::genesis_block(&params).header;
        h.version = Version::from_consensus(4);
        crate::clock::with_now(1_700_000_000, || {
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
        let mut h = crate::params::genesis_block(&rt).header;
        crate::clock::with_now(1_700_000_000, || {
            h.time = 1_700_000_000;
            h.version = Version::from_consensus(3);
            let err = check_header_version_and_future_time(&rt, Height(1), &h).unwrap_err();
            assert!(matches!(err, ConsensusError::BadVersion(3)), "{err:?}");
            h.version = Version::from_consensus(4);
            check_header_version_and_future_time(&rt, Height(1), &h).unwrap();
        });

        let main = ChainParams::mainnet();
        let mut mh = crate::params::genesis_block(&main).header;
        crate::clock::with_now(1_700_000_000, || {
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
}
