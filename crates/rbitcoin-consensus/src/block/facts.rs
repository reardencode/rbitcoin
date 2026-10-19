//! Rule decisions the confirm pipeline used to construct inline.
//!
//! Query loads rows and then calls these. A missing store row stays a store
//! error in the caller. The `if` that chooses the reject lives here.

use super::{exceeds_sigops_limit, is_final_tx, sequence_locks_satisfied};
use crate::ConsensusError;
use bitcoin::block::Header;
use bitcoin::Transaction;

pub fn reject_non_final(
    tx: &Transaction,
    block_height: u32,
    lock_time_cutoff: u32,
) -> Result<(), ConsensusError> {
    if is_final_tx(tx, block_height, lock_time_cutoff) {
        Ok(())
    } else {
        Err(ConsensusError::BadTx("bad-txns-nonfinal"))
    }
}

pub fn reject_tx_without_outputs(tx: &Transaction) -> Result<(), ConsensusError> {
    if tx.output.is_empty() {
        Err(ConsensusError::BadTx("no outputs"))
    } else {
        Ok(())
    }
}

pub fn reject_tx_without_inputs(tx: &Transaction) -> Result<(), ConsensusError> {
    if tx.input.is_empty() {
        Err(ConsensusError::BadTx("no inputs"))
    } else {
        Ok(())
    }
}

pub fn reject_assemble_block_shape(
    n_tx: usize,
    n_txid: usize,
    n_archived_fk: Option<usize>,
    first_is_coinbase: bool,
) -> Result<(), ConsensusError> {
    if let Some(n_fk) = n_archived_fk {
        if n_fk != n_tx {
            return Err(ConsensusError::BadBlock("archived tx fk count mismatch"));
        }
    }
    if n_txid != n_tx {
        return Err(ConsensusError::BadBlock(
            "invariant: create_txids length must match block.txdata (no assemble re-hash)",
        ));
    }
    if n_tx == 0 {
        return Err(ConsensusError::BadBlock("empty block"));
    }
    if !first_is_coinbase {
        return Err(ConsensusError::BadBlock("first tx not coinbase"));
    }
    Ok(())
}

pub fn add_sigops(cost: u64, legacy: u64, input: u64) -> Result<u64, ConsensusError> {
    let next = cost
        .checked_add(legacy)
        .and_then(|c| c.checked_add(input))
        .ok_or(ConsensusError::BadBlock("bad-blk-sigops"))?;
    if exceeds_sigops_limit(next) {
        return Err(ConsensusError::BadBlock("bad-blk-sigops"));
    }
    Ok(next)
}

// btc-lean: BLK-103 TXV-024
pub fn fee_from_values(value_in: i64, value_out: i64) -> Result<i64, ConsensusError> {
    if value_out > value_in {
        return Err(ConsensusError::BadTx("in < out"));
    }
    value_in
        .checked_sub(value_out)
        .ok_or(ConsensusError::BadTx("fee overflow"))
}

pub fn fee_sat(fee: i64) -> Result<u64, ConsensusError> {
    u64::try_from(fee).map_err(|_| ConsensusError::BadTx("fee overflow"))
}

pub fn add_fee(fees: i64, fee: i64) -> Result<i64, ConsensusError> {
    fees.checked_add(fee)
        .ok_or(ConsensusError::BadTx("fee overflow"))
}

pub fn add_value_in(value_in: i64, sat: u64) -> Result<i64, ConsensusError> {
    value_in
        .checked_add(sat as i64)
        .ok_or(ConsensusError::BadTx("value in overflow"))
}

// btc-lean: BLK-100 BLK-109 INV-028 INV-107 TXV-021 TXV-070
pub fn reject_genesis_coinbase_spend(is_genesis: bool) -> Result<(), ConsensusError> {
    if is_genesis {
        Err(ConsensusError::MissingPrevout)
    } else {
        Ok(())
    }
}

pub fn reject_duplicate_input(inserted: bool) -> Result<(), ConsensusError> {
    if inserted {
        Ok(())
    } else {
        Err(ConsensusError::BadTx("double spend in block"))
    }
}

/// Same-block prevout. A later create is not yet a coin. The coinbase of this
/// block is immature.
// btc-lean: BLK-095 BLK-096 BLK-098 INV-104 INV-105 INV-106 INV-113 TXV-063
pub fn reject_same_block_create(
    prev_index: usize,
    spend_index: usize,
) -> Result<(), ConsensusError> {
    if prev_index >= spend_index {
        return Err(ConsensusError::MissingPrevout);
    }
    if prev_index == 0 {
        return Err(ConsensusError::BadTx("coinbase immature"));
    }
    Ok(())
}

// btc-lean: BLK-097 BLK-099 BLK-102 BLK-110 INV-027 INV-109 INV-110 TXV-020 TXV-064 TXV-065 TXV-072
pub fn reject_unresolved_spend(missing: bool) -> Result<(), ConsensusError> {
    if missing {
        Err(ConsensusError::MissingPrevout)
    } else {
        Ok(())
    }
}

pub fn reject_unspendable_prevout(unspendable: bool) -> Result<(), ConsensusError> {
    if unspendable {
        Err(ConsensusError::MissingPrevout)
    } else {
        Ok(())
    }
}

pub fn reject_prevout_spent(spent: bool) -> Result<(), ConsensusError> {
    if spent {
        Err(ConsensusError::PrevoutSpent)
    } else {
        Ok(())
    }
}

pub fn reject_spend_cursor(in_range: bool) -> Result<(), ConsensusError> {
    if in_range {
        Ok(())
    } else {
        Err(ConsensusError::BadBlock(
            "structural spends/tx input mismatch",
        ))
    }
}

pub fn reject_csv_create_height(height: Option<u32>) -> Result<u32, ConsensusError> {
    height.ok_or(ConsensusError::BadTx("bad-txns-nonfinal"))
}

pub fn reject_sequence_locks(
    tx: &Transaction,
    prev_heights: &[u32],
    coin_mtps: &[u32],
    block_height: u32,
    prev_mtp: u32,
) -> Result<(), ConsensusError> {
    if sequence_locks_satisfied(tx, prev_heights, coin_mtps, block_height, prev_mtp) {
        Ok(())
    } else {
        Err(ConsensusError::BadTx("bad-txns-nonfinal"))
    }
}

pub fn reject_witness_before_segwit(
    has_witness: bool,
    segwit_active: bool,
) -> Result<(), ConsensusError> {
    if has_witness && !segwit_active {
        Err(ConsensusError::BadBlock("unexpected witness before segwit"))
    } else {
        Ok(())
    }
}

pub fn reject_empty_confirm_batch(empty: bool) -> Result<(), ConsensusError> {
    if empty {
        Err(ConsensusError::BadBlock("empty confirm batch"))
    } else {
        Ok(())
    }
}

pub fn require_retarget_first(
    on_boundary: bool,
    no_retarget: bool,
    first: Option<u32>,
) -> Result<Option<u32>, ConsensusError> {
    if on_boundary && !no_retarget && first.is_none() {
        Err(ConsensusError::BadHeader("missing retarget first header"))
    } else {
        Ok(first)
    }
}

pub fn reject_confirm_batch(heights: &[u32]) -> Result<(), ConsensusError> {
    if heights.is_empty() {
        return Err(ConsensusError::BadBlock("empty confirm batch"));
    }
    for w in heights.windows(2) {
        if w[1] != w[0].saturating_add(1) {
            return Err(ConsensusError::BadBlock("confirm run not contiguous"));
        }
    }
    Ok(())
}

pub fn reject_txid_count(n_tx: usize, n_txid: usize) -> Result<(), ConsensusError> {
    if n_tx == n_txid {
        Ok(())
    } else {
        Err(ConsensusError::BadBlock("txid count mismatch"))
    }
}

pub fn require_linked_parent<T>(row: Option<T>) -> Result<T, ConsensusError> {
    row.ok_or(ConsensusError::BadPrev)
}

pub fn reject_prev_link(prev: &[u8; 32], expect: &[u8; 32]) -> Result<(), ConsensusError> {
    if prev == expect {
        Ok(())
    } else {
        Err(ConsensusError::BadPrev)
    }
}

pub fn reject_carried_header_hash(
    hash: &[u8; 32],
    expect: &[u8; 32],
) -> Result<(), ConsensusError> {
    if hash == expect {
        Ok(())
    } else {
        Err(ConsensusError::BadBlock("carried header hash mismatch"))
    }
}

pub fn reject_batch_starts_at(height: u32, path_lo: u32) -> Result<(), ConsensusError> {
    if height == path_lo {
        Ok(())
    } else {
        Err(ConsensusError::BadPrev)
    }
}

/// A header window with no timestamps is not a median.
pub fn median_or_bad_header(times: &[u32]) -> Result<u32, ConsensusError> {
    crate::header::median_time_past_times(times)
        .map_err(|_| ConsensusError::BadHeader("empty median time"))
}

/// `None` from the work walk is a missing ancestor, which is `BadPrev`.
pub fn require_next_work(
    bits: Option<bitcoin::CompactTarget>,
) -> Result<bitcoin::CompactTarget, ConsensusError> {
    bits.ok_or(ConsensusError::BadPrev)
}

pub fn reject_vout_past_n_out(max_vout: u32, n_out: Option<u64>) -> Result<(), ConsensusError> {
    if n_out.is_some_and(|n| u64::from(max_vout) >= n) {
        Err(ConsensusError::MissingPrevout)
    } else {
        Ok(())
    }
}

pub fn require_same_block_output(
    tx: Option<&Transaction>,
    vout: usize,
) -> Result<&bitcoin::TxOut, ConsensusError> {
    let tx = tx.ok_or(ConsensusError::MissingPrevout)?;
    tx.output.get(vout).ok_or(ConsensusError::MissingPrevout)
}

/// Gap at or below the confirmed tip is a bad prev. Above the tip the caller
/// keeps the retryable load error.
pub fn header_gap_on_chain(height: u32, tip: u32) -> Result<(), ConsensusError> {
    if height > tip {
        Ok(())
    } else {
        Err(ConsensusError::BadPrev)
    }
}

pub fn reject_bits(
    header: &Header,
    expected: bitcoin::CompactTarget,
) -> Result<(), ConsensusError> {
    if header.bits == expected {
        Ok(())
    } else {
        Err(ConsensusError::BadHeader("incorrect proof of work bits"))
    }
}

/// Parent create_fk that the store could not resolve is a missing prevout,
/// not a corrupt row.
pub fn unresolved_parent_create() -> ConsensusError {
    ConsensusError::MissingPrevout
}
