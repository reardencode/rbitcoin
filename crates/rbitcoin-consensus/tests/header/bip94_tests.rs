use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, CompactTarget, Target, TxMerkleNode};
use rbitcoin_consensus::error::ConsensusError;
use rbitcoin_consensus::header::*;
use rbitcoin_consensus::params::ChainParams;
use rbitcoin_primitives::Height;

const PARENT_TIME: u32 = 1_714_800_000;
const PARENT_HASH: [u8; 32] = [7; 32];

/// The network's rules with the regtest pow limit, so a header grinds in a
/// few hashes. The rules under test do not read the pow limit.
fn cheap(mut params: ChainParams) -> ChainParams {
    params.pow_limit = Target::MAX_ATTAINABLE_REGTEST;
    params
}

fn header_at(time: u32) -> Header {
    let mut h = Header {
        version: Version::from_consensus(4),
        prev_blockhash: BlockHash::from_byte_array(PARENT_HASH),
        merkle_root: TxMerkleNode::from_byte_array([9; 32]),
        time,
        bits: CompactTarget::from_consensus(rbitcoin_consensus::REGTEST_POW_BITS),
        nonce: 0,
    };
    rbitcoin_consensus::grind_regtest_pow(&mut h);
    h
}

fn on_parent(params: &ChainParams, height: u32, time: u32) -> Result<(), ConsensusError> {
    let h = header_at(time);
    rbitcoin_consensus::clock::with_now(u64::from(PARENT_TIME), || {
        validate_header_on_parent(
            params,
            Height(height),
            &h,
            0,
            PARENT_TIME,
            h.bits,
            h.block_hash().to_byte_array(),
        )
    })
}

fn is_timewarp(err: &ConsensusError) -> bool {
    matches!(err, ConsensusError::BadHeader("time-timewarp-attack"))
        && rbitcoin_consensus::block_reject_reason(err) == "time-timewarp-attack"
}

/// Core `CalculateNextWorkRequired` with `enforce_BIP94`: the retarget
/// multiplies the `nBits` of the period's first block, not the parent's.
/// A two-week span leaves the target unchanged, so the result is the
/// multiplied `nBits` itself. The parent is a min-difficulty block.
#[test]
fn retarget_multiplies_the_period_first_bits_on_testnet4() {
    let first = PeriodFirst {
        time: PARENT_TIME - 1_209_600,
        bits: CompactTarget::from_consensus(0x1c1f_ffe0),
    };
    let retarget = |params: &ChainParams| {
        let limit = params.pow_limit.to_compact_lossy();
        next_work_bits(
            params,
            2016,
            limit,
            PARENT_TIME,
            PARENT_TIME + 1,
            Some(first),
            |_| None,
        )
    };
    assert_eq!(retarget(&ChainParams::testnet4()), Some(first.bits));
    assert_eq!(
        retarget(&ChainParams::testnet()),
        Some(CompactTarget::from_consensus(0x1d00_ffff)),
        "testnet3 multiplies the parent's min-difficulty bits"
    );
}

/// Core `ContextualCheckBlockHeader`: with BIP94 a period's first header is
/// at most `MAX_TIMEWARP` (600 s) before its parent.
#[test]
fn timewarp_floor_is_600_seconds_before_the_parent_on_testnet4() {
    let t4 = cheap(ChainParams::testnet4());
    on_parent(&t4, 2016, PARENT_TIME - 600).expect("600 s before the parent");
    let err = on_parent(&t4, 4032, PARENT_TIME - 601).unwrap_err();
    assert!(is_timewarp(&err), "{err:?}");
    on_parent(&t4, 2017, PARENT_TIME - 601).expect("only a period's first header");
    let t3 = cheap(ChainParams::testnet());
    on_parent(&t3, 2016, PARENT_TIME - 601).expect("testnet3 has no timewarp rule");
}

/// The confirm path (`check_header`) applies the same floor.
#[test]
fn check_header_rejects_a_timewarped_period_start() {
    let t4 = cheap(ChainParams::testnet4());
    let limit = t4.pow_limit.to_compact_lossy();
    let h = header_at(PARENT_TIME - 601);
    let err = rbitcoin_consensus::clock::with_now(u64::from(PARENT_TIME), || {
        check_header(
            &t4,
            Height(2016),
            &h,
            h.block_hash().to_byte_array(),
            Some(ParentHeader {
                hash: PARENT_HASH,
                time: PARENT_TIME,
                bits: limit,
            }),
            &[PARENT_TIME - 10_000; 11],
            Some(PeriodFirst {
                time: PARENT_TIME - 1_209_600,
                bits: limit,
            }),
            |_| Some(limit),
        )
    })
    .unwrap_err();
    assert!(is_timewarp(&err), "{err:?}");
}
