use crate::error::ConsensusError;
use crate::params::{check_genesis_hash, ChainParams};
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::{CompactTarget, Target};
use rbitcoin_primitives::Height;
pub use rbitcoin_primitives::{median_time_past_times, MedianWindow};

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
    let mtp = match MedianWindow::new(mtp_times) {
        Ok(times) => median_time_past_times(times),
        Err(_) => {
            crate::trust::soften_at(
                Some(height.0),
                ConsensusError::BadHeader("empty median time"),
            )?;
            0
        }
    };
    let mtp_failed = header.time <= mtp;
    if mtp_failed {
        crate::trust::soften_at(
            Some(height.0),
            ConsensusError::BadHeader("timestamp <= median-time-past"),
        )?;
    }
    if let Err(e) = check_header_version_and_future_time(params, height, header) {
        crate::trust::soften_at(Some(height.0), e)?;
    }

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
    // A waived median comparison still returns the window it checked. `0` is
    // only the empty-window case above. Callers use this as the next cutoff.
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
        crate::trust::soften_at(
            Some(height.0),
            ConsensusError::BadHeader("timestamp <= median-time-past"),
        )?;
    }
    if let Err(e) = check_header_version_and_future_time(params, height, header) {
        crate::trust::soften_at(Some(height.0), e)?;
    }
    if header.bits != expected_bits {
        return Err(ConsensusError::BadHeader("incorrect proof of work bits"));
    }
    pow_hash_meets_target(
        header.block_hash().to_byte_array(),
        header.bits,
        params.pow_limit,
    )?;
    Ok(())
}

/// POW vs a **caller-computed** header hash (no second SHA256d).
pub fn pow_hash_meets_target(
    hash: [u8; 32],
    bits: CompactTarget,
    pow_limit: Target,
) -> Result<(), ConsensusError> {
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
/// `validate_header` (MTP walk + header rehash).
pub fn check_header_version_and_future_time(
    params: &ChainParams,
    height: Height,
    header: &Header,
) -> Result<(), ConsensusError> {
    const MAX_FUTURE_BLOCK_TIME: u64 = 2 * 60 * 60;
    let now = crate::clock::current_now();
    if u64::from(header.time) > now.saturating_add(MAX_FUTURE_BLOCK_TIME) {
        return Err(ConsensusError::BadHeader("timestamp too far in future"));
    }
    let ver = header.version.to_consensus();
    if (params.bip34_active_at(height.0) && ver < 2)
        || (params.bip66_active_at(height.0) && ver < 3)
        || (params.bip65_active_at(height.0) && ver < 4)
    {
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
    Some(CompactTarget::from_next_work_required(
        prev_bits,
        timespan,
        &params.btc,
    ))
}

#[doc(hidden)]
pub fn min_diff_bits(
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
