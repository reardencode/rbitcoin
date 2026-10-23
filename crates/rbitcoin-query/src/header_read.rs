//! Header reads. Decisions are [`rbitcoin_consensus::check_header`].

use crate::ConfirmError;
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::CompactTarget;
use rbitcoin_consensus::header::{check_header, next_work_bits, ParentHeader};
use rbitcoin_consensus::ChainParams;
use rbitcoin_primitives::Height;

use crate::Query;

pub fn validate_header(
    query: &Query,
    params: &ChainParams,
    height: Height,
    header: &Header,
) -> Result<(), ConfirmError> {
    validate_header_hashed(
        query,
        params,
        height,
        header,
        header.block_hash().to_byte_array(),
    )
}

/// [`validate_header`] using a caller-computed header hash (lookup already hashed).
pub fn validate_header_hashed(
    query: &Query,
    params: &ChainParams,
    height: Height,
    header: &Header,
    hash: [u8; 32],
) -> Result<(), ConfirmError> {
    let parent = if height.0 == 0 {
        None
    } else {
        query
            .header_at_height(Height(height.0 - 1))?
            .map(|(_fk, prev)| ParentHeader {
                hash: prev.hash,
                time: prev.timestamp,
                bits: CompactTarget::from_consensus(prev.bits),
            })
    };
    let times = if parent.is_some() {
        mtp_times_ending_at(query, Height(height.0 - 1))?
    } else {
        Vec::new()
    };
    let period_first = if parent.is_some() {
        period_first_time(query, params, height.0)?
    } else {
        None
    };
    let period_open = if parent.is_some() {
        period_open_time(query, params, height.0)?
    } else {
        None
    };
    let own_guard = crate::confirm_run::confirm_waive(query) && !rbitcoin_consensus::collecting();
    let guard = own_guard.then(rbitcoin_consensus::TrustCollect::enter);
    let result = check_header(
        params,
        height,
        header,
        hash,
        parent,
        &times,
        period_first,
        period_open,
        |h| {
            header_bits_at(query, Height(h))
                .ok()
                .map(CompactTarget::from_consensus)
        },
    )
    .map(|_| ())
    .map_err(ConfirmError::from);
    if own_guard {
        let applied = result.is_ok();
        let stopped = match &result {
            Err(ConfirmError::Rules(err)) => Some(err),
            _ => None,
        };
        crate::confirm_run::log_collected_header(hash, height.0, applied, stopped);
        drop(guard);
    }
    result
}

/// Contextual checks when the parent is a known header, not necessarily on the
/// best chain (`header_at_height` would miss).
pub fn median_time_past(query: &Query, height: Height) -> Result<u32, ConfirmError> {
    let times = mtp_times_ending_at(query, height)?;
    rbitcoin_consensus::block::median_or_bad_header(&times).map_err(ConfirmError::from)
}

/// Timestamps ending at `height` for [`median_time_past`]. A missing plan above
/// the confirmed tip stays a retryable load fault. A gap at or below the tip
/// is `ConsensusError::BadPrev`.
pub fn mtp_times_ending_at(query: &Query, height: Height) -> Result<Vec<u32>, ConfirmError> {
    if let Some((n, buf)) = query.store().mtp_times_at(height) {
        return Ok(buf[..n as usize].to_vec());
    }
    let mut times = Vec::with_capacity(11);
    let start = height.0.saturating_sub(10);
    let tip = query.tip_height().map(|h| h.0).unwrap_or(0);
    for h in start..=height.0 {
        if let Some((_fk, rec)) = query.header_at_height(Height(h))? {
            times.push(rec.timestamp);
            continue;
        }
        if let Some(plan) = query.confirm_parent_cache().get_header_plan(h) {
            times.push(plan.header_rec.timestamp);
            continue;
        }
        rbitcoin_consensus::block::header_gap_on_chain(h, tip)?;
        return Err(ConfirmError::Store(rbitcoin_store::StoreError::Corrupt(
            "confirm: load incomplete (parent header plan missing above tip)",
        )));
    }
    Ok(times)
}

/// MTP from the confirmed chain only (write structural). Tip-ahead heights
/// must be carried on [`crate::confirm_run`] `Prepared::prev_mtp`.
pub fn median_time_past_store(query: &Query, height: Height) -> Result<u32, ConfirmError> {
    if let Some((n, buf)) = query.store().mtp_times_at(height) {
        return rbitcoin_consensus::block::median_or_bad_header(&buf[..n as usize])
            .map_err(ConfirmError::from);
    }
    let mut times = Vec::with_capacity(11);
    let start = height.0.saturating_sub(10);
    for h in start..=height.0 {
        if let Some((_fk, rec)) = query.header_at_height(Height(h))? {
            times.push(rec.timestamp);
            continue;
        }
        return Err(ConfirmError::Store(rbitcoin_store::StoreError::Corrupt(
            "confirm: write MTP missing confirmed header (carry prev_mtp)",
        )));
    }
    rbitcoin_consensus::block::median_or_bad_header(&times).map_err(ConfirmError::from)
}

/// Expected `nBits` for a new header at `height`.
///
/// `header_time` is the candidate block's timestamp (Core `pblock->GetBlockTime()`).
pub fn expected_next_bits(
    query: &Query,
    params: &ChainParams,
    height: Height,
    header_time: u32,
) -> Result<CompactTarget, ConfirmError> {
    if height.0 == 0 {
        let g = rbitcoin_consensus::genesis_block(params);
        return Ok(g.header.bits);
    }

    let prev_height = Height(height.0 - 1);
    let (_fk, prev_rec) =
        rbitcoin_consensus::block::require_linked_parent(query.header_at_height(prev_height)?)?;
    let prev_bits = CompactTarget::from_consensus(prev_rec.bits);
    let period_first = period_first_time(query, params, height.0)?;
    rbitcoin_consensus::block::require_next_work(next_work_bits(
        params,
        height.0,
        prev_bits,
        prev_rec.timestamp,
        header_time,
        period_first,
        |h| {
            header_bits_at(query, Height(h))
                .ok()
                .map(CompactTarget::from_consensus)
        },
    ))
    .map_err(ConfirmError::from)
}

/// Difficulty for the header at `height`, from the parent and the period start.
///
/// `period_first_time` is the timestamp of the header at `height - interval`
/// when `height` is a retarget boundary. `bits_at` supplies earlier `nBits`
/// for the testnet min-difficulty walk. `None` means an ancestor is missing.
/// Timestamp of the first block of the difficulty period, when BIP 54's
/// negative-interval check applies. Missing when the check applies is a
/// header failure.
pub fn period_open_time(
    query: &Query,
    params: &ChainParams,
    height: u32,
) -> Result<Option<u32>, ConfirmError> {
    let Some(open_h) = params.bip54_period_open_height(height) else {
        return Ok(None);
    };
    if let Some((_fk, rec)) = query.header_at_height(Height(open_h))? {
        return Ok(Some(rec.timestamp));
    }
    if let Some(plan) = query.confirm_parent_cache().get_header_plan(open_h) {
        return Ok(Some(plan.header_rec.timestamp));
    }
    Err(ConfirmError::from(
        rbitcoin_consensus::ConsensusError::BadHeader("missing bip54 period open"),
    ))
}

pub fn period_first_time(
    query: &Query,
    params: &ChainParams,
    height: u32,
) -> Result<Option<u32>, ConfirmError> {
    let interval = params.difficulty_adjustment_interval();
    if interval == 0 || !height.is_multiple_of(interval) || params.no_pow_retargeting() {
        return Ok(None);
    }
    Ok(query
        .header_at_height(Height(height - interval))?
        .map(|(_fk, first_rec)| first_rec.timestamp))
}

pub fn header_bits_at(query: &Query, height: Height) -> Result<u32, ConfirmError> {
    if let Some((_fk, rec)) = query.header_at_height(height)? {
        return Ok(rec.bits);
    }
    if let Some(plan) = query.confirm_parent_cache().get_header_plan(height.0) {
        return Ok(plan.header_rec.bits);
    }
    rbitcoin_consensus::block::require_linked_parent(None).map_err(ConfirmError::from)
}
