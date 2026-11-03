//! Block and transaction validation / confirmability.

pub mod block;
#[doc(hidden)]
pub mod clock;
#[doc(hidden)]
pub mod error;
pub mod header;
#[doc(hidden)]
pub mod id_map;
#[doc(hidden)]
pub mod milestone;
#[doc(hidden)]
pub mod params;
pub mod policy;
#[doc(hidden)]
pub mod regtest_pad;
#[doc(hidden)]
pub mod script;
#[cfg(feature = "corpus")]
pub use script::core_script;
pub mod script_pool;
#[doc(hidden)]
pub mod signet;
pub mod silent_payments;
#[doc(hidden)]
pub mod sync;
#[doc(hidden)]
pub mod trust;
#[doc(hidden)]
pub mod tx_precompute;

pub use block::ScriptCheckJob;

/// Consensus script verify for a single tx on the shared `rbtc-scripts` path.
///
/// Always hops to a detached script worker (same naming/pool family as IBD
/// confirm scripts). Callers on peer sessions or tokio request threads must use
/// this (or equivalent) — never run the interpreter on the I/O stack.
pub fn verify_tx_scripts_detached(
    prevouts: Vec<bitcoin::TxOut>,
    tx: bitcoin::Transaction,
) -> Result<(), ConsensusError> {
    verify_tx_scripts_detached_forks(prevouts, tx, true, true, true, true, true)
}

fn verify_scripts_with_flags(
    prevouts: Vec<bitcoin::TxOut>,
    tx: bitcoin::Transaction,
    flags: crate::block::ScriptVerifyFlags,
) -> Result<(), ConsensusError> {
    let job = ScriptCheckJob::try_new(prevouts, tx, flags)?;
    crate::script::verify_job_all_inputs(&job)
}

/// Same worker path as [`verify_tx_scripts_detached`] with explicit buried-fork flags.
pub fn verify_tx_scripts_detached_forks(
    prevouts: Vec<bitcoin::TxOut>,
    tx: bitcoin::Transaction,
    bip65_active: bool,
    bip112_active: bool,
    bip66_active: bool,
    bip16_active: bool,
    taproot_active: bool,
) -> Result<(), ConsensusError> {
    script_pool::run_detached_join(move || {
        verify_scripts_with_flags(
            prevouts,
            tx,
            crate::block::ScriptVerifyFlags::buried(
                bip65_active,
                bip112_active,
                bip66_active,
                bip16_active,
                taproot_active,
            ),
        )
    })
    .unwrap_or(Err(ConsensusError::BadBlock("script worker disconnected")))
}

/// Await [`verify_tx_scripts_detached`] on `rbtc-scripts-*` without a blocking thread.
///
/// The caller parks. Mempool admit uses this from the request task. Sync admit
/// keeps [`verify_tx_scripts_detached`].
pub async fn verify_tx_scripts_cpu(
    prevouts: Vec<bitcoin::TxOut>,
    tx: bitcoin::Transaction,
) -> Result<(), ConsensusError> {
    script_pool::run_cpu(move || {
        verify_scripts_with_flags(
            prevouts,
            tx,
            crate::block::ScriptVerifyFlags::buried(true, true, true, true, true),
        )
    })
    .await
    .unwrap_or(Err(ConsensusError::BadBlock("script worker disconnected")))
}

/// Same worker as [`verify_tx_scripts_detached`], with the caller's flag word.
///
/// Block confirm and mempool admission keep [`ScriptVerifyFlags::consensus_at`]
/// and [`ScriptVerifyFlags::buried`]. This entry exists so an in-process oracle
/// can apply policy bits and pre-activation witness without those paths changing.
pub fn verify_tx_scripts_with_flags(
    prevouts: Vec<bitcoin::TxOut>,
    tx: bitcoin::Transaction,
    flags: crate::block::ScriptVerifyFlags,
) -> Result<(), ConsensusError> {
    script_pool::run_detached_join(move || verify_scripts_with_flags(prevouts, tx, flags))
        .unwrap_or(Err(ConsensusError::BadBlock("script worker disconnected")))
}

pub use block::validate_block_structure_hashed;
pub use block::{
    bip34_height_script, bip68_active_for_tx, block_has_witness, block_mutated_without_coinbase,
    block_subsidy, check_block_wire, is_final_tx, sequence_locks_satisfied, tx_sigop_cost,
    validate_block_structure, witness_commitment_script, witness_commitment_vout_index, InputIndex,
    ScriptVerifyFlags, ValidationContext, BIP16_EXCEPTION_MAINNET, MAX_BLOCK_TX_COUNT,
    MAX_BLOCK_WEIGHT, MIN_TX_WEIGHT, TAPROOT_EXCEPTION_MAINNET,
};
pub use clock::{with_now, NodeClock};
pub use error::{block_reject_log_line, block_reject_reason, script_flag_paren, ConsensusError};
pub use header::{check_header, next_work_bits, validate_header_on_parent, ParentHeader};
pub use id_map::{IdMap, OutPointHasher, OutPointSet, TxidHasher, TxidMap, TxidSet};
pub use milestone::{Milestone, MilestoneAnchor};
pub use params::{
    default_milestone_anchor, default_milestone_height, default_min_chain_work_be, genesis_block,
    Bip9Deployment, ChainParams, MAINNET_MILESTONE_HASH, TESTNET_MILESTONE_HASH,
};
pub use policy::PolicyResult;
pub use regtest_pad::{
    grind_regtest_pow, mine_empty_regtest, mine_op_true_signet_paying, mine_regtest_paying,
    mine_regtest_paying_bits, prepare_regtest_candidate, regtest_coinbase,
    try_mine_regtest_paying_bits, REGTEST_BLOCK_SPACING, REGTEST_POW_BITS,
};
pub use script_pool::unpark_script_publisher;
pub use signet::{
    default_signet_challenge, signet_challenge_transactions, signet_magic,
    validate_signet_block_solution,
};
pub use silent_payments::{taproot_matches_scan, tweak_from_tx, TaprootOut, TxTweak};
pub use trust::{
    collecting, current_block_height, drain_warnings, is_warn_and_apply, note_block_height,
    reason_is_warn_and_apply, soften, soften_at, TrustCollect,
};
pub use tx_precompute::{
    block_wire_len_from_pres, decode_block_precomputes, pres_for_tip, TxConnectPrecompute,
    TxPrecompute, TxScriptPrecompute,
};
