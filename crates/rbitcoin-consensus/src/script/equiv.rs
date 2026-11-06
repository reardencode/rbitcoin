//! Consensus-only script check for an external equivalence proof.
//!
//! The node build leaves the `equiv` feature off. This calls
//! [`super::verify_input`] with the interpreter forced. It does not spawn a
//! worker and it does not catch panics.

use bitcoin::{Transaction, TxOut};

use super::script_fail::consensus_ordinal;
use super::verify_input;
use crate::block::{InputIndex, ScriptCheckJob, ScriptVerifyFlags};
use crate::error::ConsensusError;

/// Bitcoin Core `SCRIPT_VERIFY_*` bits that are consensus rules.
///
/// Positions are `1 <<` the `ScriptVerificationFlags` ordinal in Core v32.1
/// `interpreter.h`: `P2SH`, `DERSIG`, `NULLDUMMY`, `CLTV`, `CSV`, `WITNESS`,
/// `TAPROOT`.
pub const EQUIV_ALLOWED: u64 =
    (1 << 0) | (1 << 2) | (1 << 4) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 17);

/// Core `SCRIPT_ERR_UNKNOWN_ERROR`.
const UNKNOWN_ERROR: i32 = 1;

/// Why a proof check did not accept the spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EquivFail {
    /// Flag word, input index, or prevout count is not a consensus input.
    BadInput,
    /// Core `ScriptError` ordinal.
    Script(i32),
}

/// Check one input. `flags` is the Core script-verify bitset.
///
/// Any bit outside [`EQUIV_ALLOWED`] returns [`EquivFail::BadInput`] before
/// the checker runs. `prevouts` is every input's prevout, in `vin` order.
pub fn equiv_verify(
    tx: &Transaction,
    prevouts: &[TxOut],
    input_index: u32,
    flags: u64,
) -> Result<(), EquivFail> {
    if prevouts.len() != tx.input.len() {
        return Err(EquivFail::BadInput);
    }
    let index = input_index as usize;
    if index >= tx.input.len() {
        return Err(EquivFail::BadInput);
    }
    if flags & !EQUIV_ALLOWED != 0 {
        return Err(EquivFail::BadInput);
    }
    let script_flags = ScriptVerifyFlags {
        bip16_active: flags & (1 << 0) != 0,
        bip66_active: flags & (1 << 2) != 0,
        null_dummy: flags & (1 << 4) != 0,
        bip65_active: flags & (1 << 9) != 0,
        bip112_active: flags & (1 << 10) != 0,
        witness_active: flags & (1 << 11) != 0,
        taproot_active: flags & (1 << 17) != 0,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        minimal_data: false,
        witness_pubkeytype: false,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        cleanstack: false,
    };
    let mut job = ScriptCheckJob::try_new(prevouts.to_vec(), tx.clone(), script_flags)
        .map_err(|_| EquivFail::BadInput)?;
    job.interpreter_only = true;
    let ii = InputIndex::in_tx(tx, index).map_err(|_| EquivFail::BadInput)?;
    let mut cache = None;
    let pre = if crate::tx_precompute::uses_segwit_serialization(tx) {
        job.pre().map_err(script_ordinal)?
    } else {
        super::interpreter::base_sig_precompute()
    };
    let tap_spent = super::crypto::TapSpentHashes::default();
    verify_input(&job, ii, tx, &mut cache, pre, &tap_spent).map_err(script_ordinal)
}

fn script_ordinal(err: ConsensusError) -> EquivFail {
    match err {
        ConsensusError::Script(msg) => {
            EquivFail::Script(consensus_ordinal(&msg).unwrap_or(UNKNOWN_ERROR))
        }
        _ => EquivFail::Script(UNKNOWN_ERROR),
    }
}
