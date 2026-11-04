//! `--trust-peer` collects warn-and-apply faults and lets the caller continue.
//!
//! The flag-off path never enters [`TrustCollect`]. [`soften`] then returns
//! the original error and does not record it. Success paths do not call
//! [`soften`].

use crate::error::{block_reject_reason, ConsensusError};
use std::cell::{Cell, RefCell};
use std::collections::HashSet;

thread_local! {
    static DEPTH: Cell<u32> = const { Cell::new(0) };
    static WARNS: RefCell<Vec<(Option<u32>, ConsensusError)>> = const { RefCell::new(Vec::new()) };
    /// Block height of the check currently running on this thread.
    static CUR_HEIGHT: Cell<Option<u32>> = const { Cell::new(None) };
}

/// Remember `height` while a collector is active, so a [`soften`] with no
/// explicit height is attributed to this block.
pub fn note_block_height(height: u32) {
    if collecting() {
        CUR_HEIGHT.with(|c| c.set(Some(height)));
    }
}

pub fn current_block_height() -> Option<u32> {
    CUR_HEIGHT.with(|c| c.get())
}

/// Enables [`soften`] on this thread until dropped.
pub struct TrustCollect;

impl TrustCollect {
    pub fn enter() -> Self {
        DEPTH.with(|d| d.set(d.get().saturating_add(1)));
        Self
    }
}

impl Drop for TrustCollect {
    fn drop(&mut self) {
        DEPTH.with(|d| {
            let n = d.get().saturating_sub(1);
            d.set(n);
            if n == 0 {
                WARNS.with(|w| w.borrow_mut().clear());
                CUR_HEIGHT.with(|c| c.set(None));
            }
        });
    }
}

pub fn collecting() -> bool {
    DEPTH.with(|d| d.get() > 0)
}

/// Keep `err` and continue when trust-peer collection is on and the fault is
/// warn-and-apply. Otherwise return `err`.
pub fn soften(err: ConsensusError) -> Result<(), ConsensusError> {
    soften_at(None, err)
}

pub fn soften_at(height: Option<u32>, err: ConsensusError) -> Result<(), ConsensusError> {
    if !collecting() || !is_warn_and_apply(&err) {
        return Err(err);
    }
    let height = height.or_else(current_block_height);
    WARNS.with(|w| w.borrow_mut().push((height, err)));
    Ok(())
}

/// Faults recorded since [`TrustCollect::enter`], first occurrence of each
/// height and reject reason.
pub fn drain_warnings() -> Vec<(Option<u32>, ConsensusError)> {
    let mut v = WARNS.with(|w| std::mem::take(&mut *w.borrow_mut()));
    let mut seen = HashSet::new();
    v.retain(|(h, e)| seen.insert((*h, block_reject_reason(e))));
    v
}

fn apply_header(s: &str) -> bool {
    matches!(
        s,
        "timestamp <= median-time-past"
            | "timestamp too far in future"
            | "empty median time"
            | "time-too-old"
            | "time-too-new"
            | "time-timewarp-attack"
    )
}

fn apply_block(s: &str) -> bool {
    matches!(
        s,
        "bip34 height encoding"
            | "bip34 coinbase script empty"
            | "bad-cb-height"
            | "bad-blk-sigops"
            | "coinbase excess value"
            | "bad-cb-amount"
            | "signet solution invalid"
            | "bad-signet-blksig"
    ) || s.starts_with("signet:")
}

fn apply_tx(s: &str) -> bool {
    matches!(
        s,
        "not final"
            | "bad-txns-nonfinal"
            | "coinbase immature"
            | "bad-txns-BIP30"
            | "bad-txns-premature-spend-of-coinbase"
            | "non-BIP68-final"
    )
}

/// Warn-and-apply versus warn-and-stop. Stop-class faults stay `Err`.
///
/// The class is the reject string, so a Core rename cannot be warn-class here
/// and hard on the mempool path.
pub fn is_warn_and_apply(err: &ConsensusError) -> bool {
    reason_is_warn_and_apply(&crate::block_reject_reason(err))
}

/// Public reject text for a warn-and-apply fault.
///
/// Block connect classifies [`ConsensusError`]. Proposals and the mempool
/// speak Core strings (`bad-cb-amount`, `time-too-old`). Proof-of-work
/// (`high-hash`, `bad-diffbits`) and a body that does not match its header
/// stay hard on both paths.
pub fn reason_is_warn_and_apply(reason: &str) -> bool {
    reason.contains("script verification")
        || reason.starts_with("block-script-verify")
        || reason.starts_with("bad-version")
        || apply_header(reason)
        || apply_block(reason)
        || apply_tx(reason)
}
