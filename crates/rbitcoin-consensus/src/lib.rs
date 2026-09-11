//! Block and transaction validation / confirmability.

mod block;
mod clock;
mod confirm_run;
mod convert;
mod error;
mod header;
mod milestone;
mod params;
pub mod policy;
mod regtest_pad;
mod script;
mod script_pool;
mod signet;
pub mod silent_payments;

pub(crate) use block::ScriptCheckJob;

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
        let job = ScriptCheckJob::new(
            prevouts,
            tx,
            crate::block::ScriptVerifyFlags::buried(
                bip65_active,
                bip112_active,
                bip66_active,
                bip16_active,
                taproot_active,
            ),
        );
        crate::script::verify_job_all_inputs(&job)
    })
    .unwrap_or_else(|| Err(ConsensusError::BadBlock("script worker disconnected")))
}

pub use block::{
    bip34_height_script, bip68_active_for_tx, block_has_witness, block_subsidy, check_block_wire,
    is_final_tx, sequence_locks_satisfied, tx_gbt_sigops, validate_block_structure,
    witness_commitment_script, ValidationContext,
};
pub(crate) use block::{validate_block_structure_hashed, TxPrecompute};
pub use clock::{with_now, NodeClock};
pub use convert::header_to_record;
pub(crate) use convert::{
    block_to_apply, block_to_apply_with_txids, block_to_apply_with_txids_prev,
};
pub use error::{block_reject_log_line, block_reject_reason, script_flag_paren, ConsensusError};
pub use header::{expected_next_bits, median_time_past, validate_header};
pub use milestone::Milestone;
pub use params::{default_milestone_height, genesis_block, ChainParams, Checkpoint};
pub use policy::PolicyResult;
pub use regtest_pad::{
    grind_regtest_pow, mine_empty_regtest, mine_regtest_paying, pad_empty_from,
    prepare_regtest_candidate, REGTEST_BLOCK_SPACING,
};
pub use signet::signet_magic;
pub use silent_payments::{
    backfill_sp_tweaks_cancellable, tweak_from_tx, tweaks_for_height, TaprootOut, TxTweak,
};

use bitcoin::hashes::Hash;
use bitcoin::{Block, Target};
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::{Query, TxApply};
use rbitcoin_store::HeaderRecord;

/// Test-only assemble cold-why / batch TLS (window meters live on Query).
#[cfg(test)]
pub mod confirm_phase_stats {
    use std::cell::Cell;

    thread_local! {
        static TL_COLD_WHY: Cell<(u64, u64, u64, u64)> =
            const { Cell::new((0, 0, 0, 0)) };
        static TL_BATCH_N: Cell<u64> = const { Cell::new(0) };
        static TL_COLD_N: Cell<u64> = const { Cell::new(0) };
    }

    #[inline]
    pub fn tl_note_cold_why_null_fk() {
        TL_COLD_WHY.with(|c| {
            let (a, b, c2, d) = c.get();
            c.set((a + 1, b, c2, d));
        });
        TL_COLD_N.with(|c| c.set(c.get() + 1));
    }
    #[inline]
    pub fn tl_note_cold_why_not_pin() {
        TL_COLD_WHY.with(|c| {
            let (a, b, c2, d) = c.get();
            c.set((a, b + 1, c2, d));
        });
        TL_COLD_N.with(|c| c.set(c.get() + 1));
    }
    #[inline]
    pub fn tl_note_cold_why_txid_mismatch() {
        TL_COLD_WHY.with(|c| {
            let (a, b, c2, d) = c.get();
            c.set((a, b, c2 + 1, d));
        });
        TL_COLD_N.with(|c| c.set(c.get() + 1));
    }
    #[inline]
    pub fn tl_note_cold_why_vout_miss() {
        TL_COLD_WHY.with(|c| {
            let (a, b, c2, d) = c.get();
            c.set((a, b, c2, d + 1));
        });
        TL_COLD_N.with(|c| c.set(c.get() + 1));
    }
    #[inline]
    pub fn tl_note_batch_hit() {
        TL_BATCH_N.with(|c| c.set(c.get() + 1));
    }
    #[inline]
    pub fn sample_tl_assemble_cold_why_and_reset() -> (u64, u64, u64, u64) {
        TL_COLD_WHY.with(|c| c.replace((0, 0, 0, 0)))
    }
    #[inline]
    pub fn sample_tl_batch_cold_n_and_reset() -> (u64, u64) {
        let b = TL_BATCH_N.with(|c| c.replace(0));
        let cold = TL_COLD_N.with(|c| c.replace(0));
        (b, cold)
    }
}

/// Confirm a contiguous tip-extension run of wire blocks (sync all stages).
///
/// See [`confirm_wire_run`]: lookup → load → scripts → write. IBD uses the split
/// phases for pipeline overlap.
pub use confirm_run::{
    confirm_bq_resolve_wave_capped, confirm_scripts_phase, confirm_wire_load_from_plan,
    confirm_wire_load_phase, confirm_wire_load_phase_pipelined, confirm_wire_lookup_stamp,
    confirm_wire_run, confirm_wire_run_preverified, confirm_write_phase, drive_script_waves_with,
    take_wave_items_for_load, ConfirmLoadOutcome, ConfirmScriptOutcome, LoadedBatch,
    PlanStampOutcome, ScriptOkBatch, ScriptPreverified, WireLoadPipeline,
    BQ_RESOLVE_WAVE_MAX_BLOCKS, BQ_RESOLVE_WAVE_MAX_INPUTS,
};

/// Wake the IBD scripts publisher (`ibd-confirm`) after `scriptq` send or close.
pub use script_pool::unpark_script_publisher;

/// Accept + archive + confirm in one step (genesis / tip extension / tests).
///
/// **Same path as IBD confirm:** structure + header checks, then Class A
/// archive, then [`confirm_wire_run`] (lookup → load pin denserels → scripts →
/// structural → Class C → abs spend annotate). No separate
/// `put_spend_batch_by_create`.
///
/// Idempotent when `height` is already confirmed for this block hash.
/// Full script verify (no mempool skip) — use
/// [`accept_and_connect_block_preverified`] on tip follow with a live mempool.
pub fn accept_and_connect_block(
    query: &Query,
    params: &ChainParams,
    height: Height,
    block: &Block,
    milestone: Milestone,
) -> Result<rbitcoin_primitives::Fk, ConsensusError> {
    accept_and_connect_block_preverified(
        query,
        params,
        height,
        block,
        milestone,
        &ScriptPreverified::new(),
    )
}

/// Like [`accept_and_connect_block`], skipping script verify for `preverified`
/// txids (tip follow: live mempool after accept). Reorg disconnect stays outside.
pub fn accept_and_connect_block_preverified(
    query: &Query,
    params: &ChainParams,
    height: Height,
    block: &Block,
    milestone: Milestone,
    preverified: &ScriptPreverified,
) -> Result<rbitcoin_primitives::Fk, ConsensusError> {
    let hash = block.block_hash().to_byte_array();
    if let Some(h) = query.height_of_hash(&hash).map_err(ConsensusError::from)? {
        if h == height {
            if let Some((fk, _)) = query
                .get_header_by_hash(&hash)
                .map_err(ConsensusError::from)?
            {
                return Ok(fk);
            }
        }
    }

    // Unified height-ordered path: wire → lookup → load (pin+assemble) → scripts →
    // write (Class A + structural + Class C + annotate). No archive-then-reload.
    let fks = confirm_wire_run_preverified(
        query,
        params,
        milestone,
        &[(height, block.clone())],
        preverified,
    )?;
    if let Some(fk) = fks.into_iter().next() {
        return Ok(fk);
    }
    // Write skipped heights ≤ tip (idempotent race). A body we just ran
    // through lookup/load must have a header — missing is an invariant, not
    // a soft NotFound (inflated confirmed[] used to hit this on tip+1).
    query
        .get_header_by_hash(&hash)
        .map_err(ConsensusError::from)?
        .map(|(fk, _)| fk)
        .ok_or(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
            "invariant: confirm write skipped but header missing",
        )))
}

fn class_a_header_and_txids(
    query: &Query,
    params: &ChainParams,
    block: &Block,
) -> Result<(HeaderRecord, Vec<[u8; 32]>), ConsensusError> {
    let ctx = ValidationContext::archive_structure(params);
    let txids = validate_block_structure_hashed(block, &ctx)?;
    let target = Target::from_compact(block.header.bits);
    if target > params.pow_limit {
        return Err(ConsensusError::BadHeader("target above pow limit"));
    }
    block
        .header
        .validate_pow(target)
        .map_err(|_| ConsensusError::InvalidPow)?;
    let prev = block.header.prev_blockhash;
    let prev_fk = if prev.to_byte_array() == [0u8; 32] {
        Fk::NULL
    } else {
        query
            .get_header_by_hash(prev.as_byte_array())
            .map_err(ConsensusError::from)?
            .map(|(fk, _)| fk)
            .ok_or(ConsensusError::BadPrev)?
    };
    Ok((header_to_record(prev_fk, &block.header), txids))
}

/// Class A only (no tip / Class C). Crash and `plan=None` tests.
///
/// Not a production IBD API — confirm write uses `archive_plan_batch_from_wire`
/// + fill packed ins + commit.
pub fn commit_class_a_block(
    query: &Query,
    params: &ChainParams,
    height: Height,
    block: &Block,
    milestone: Milestone,
) -> Result<(), ConsensusError> {
    let _ = (height, milestone);
    let (header, txids) = class_a_header_and_txids(query, params, block)?;
    let fk = query.ensure_header(&header).map_err(ConsensusError::from)?;
    query
        .archive_class_a_from_wire(&[(fk, block, txids.as_slice())])
        .map_err(ConsensusError::from)?;
    Ok(())
}

/// Class A for a contiguous run in one plan (same-batch parent stamp).
///
/// Use this instead of N×[`commit_class_a_block`] when later blocks spend
/// earlier unconfirmed creates.
pub fn commit_class_a_run(
    query: &Query,
    params: &ChainParams,
    blocks: &[(Height, Block)],
    milestone: Milestone,
) -> Result<(), ConsensusError> {
    let _ = milestone;
    let mut owned: Vec<(Fk, &Block, Vec<[u8; 32]>)> = Vec::with_capacity(blocks.len());
    for (_, block) in blocks {
        let (header, txids) = class_a_header_and_txids(query, params, block)?;
        let fk = query.ensure_header(&header).map_err(ConsensusError::from)?;
        owned.push((fk, block, txids));
    }
    let refs: Vec<(Fk, &Block, &[[u8; 32]])> = owned
        .iter()
        .map(|(fk, b, ids)| (*fk, *b, ids.as_slice()))
        .collect();
    query
        .archive_class_a_from_wire(&refs)
        .map_err(ConsensusError::from)?;
    Ok(())
}

/// CPU-side prep for Class A archive.
pub fn prepare_block_for_archive(
    query: &Query,
    params: &ChainParams,
    block: &Block,
) -> Result<(HeaderRecord, Vec<TxApply>), ConsensusError> {
    let hash = block.block_hash().to_byte_array();
    if query
        .is_block_archived(&hash)
        .map_err(ConsensusError::from)?
    {
        // Standalone archive helper (not confirm pipeline): one hash pass here.
        return block_to_apply(query, &block.header, &block.txdata);
    }
    prepare_block_for_archive_new(query, params, block)
}

pub fn prepare_block_for_archive_new(
    query: &Query,
    params: &ChainParams,
    block: &Block,
) -> Result<(HeaderRecord, Vec<TxApply>), ConsensusError> {
    let (header, txids) = class_a_header_and_txids(query, params, block)?;
    let (_, txs) =
        block_to_apply_with_txids_prev(header.prev_fk, &block.header, &block.txdata, &txids)?;
    Ok((header, txs))
}

/// Confirm wire plan: encode `TxApply` from **already-computed** structure txids.
///
/// Callers that already ran [`validate_block_structure_hashed`] must use this so
/// the confirm pipeline hashes each create **exactly once**.
pub fn prepare_block_for_archive_with_txids(
    query: &Query,
    block: &Block,
    txids: &[[u8; 32]],
) -> Result<(HeaderRecord, Vec<TxApply>), ConsensusError> {
    if block.txdata.len() != txids.len() {
        return Err(ConsensusError::BadBlock("txid count mismatch"));
    }
    block_to_apply_with_txids(query, &block.header, &block.txdata, txids)
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, Block, BlockHash, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn,
        TxMerkleNode, TxOut, Witness,
    };
    use rbitcoin_primitives::Height;
    use rbitcoin_query::Query;
    use std::path::PathBuf;
    fn temp_store() -> (PathBuf, Query) {
        let path = std::env::temp_dir().join(format!(
            "rbitcoin-consensus-cov-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path).unwrap();
        let q = Query::open_or_create_tiny(&path).expect("open store");
        (path, q)
    }

    fn mine_regtest(prev: BlockHash, time: u32, height: u32, extras: Vec<Transaction>) -> Block {
        let mut ss = if height == 0 {
            vec![0x00]
        } else {
            bip34_height_script(height)
        };
        while ss.len() < 2 {
            ss.push(0x00);
        }
        let mut txdata = vec![Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(ss),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }];
        txdata.extend(extras);
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let mut block = Block {
            header: Header {
                version: Version::from_consensus(4),
                prev_blockhash: prev,
                merkle_root: TxMerkleNode::from_byte_array([0; 32]),
                time,
                bits,
                nonce: 0,
            },
            txdata,
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        let target = Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            block.header.nonce = nonce;
            if block.header.validate_pow(target).is_ok() {
                break;
            }
        }
        block
    }

    #[test]
    fn last_write_phase_stats() {
        use rbitcoin_query::{note_confirm, ConfirmStats, LastWritePhases};
        use std::sync::atomic::Ordering;
        let st = ConfirmStats::default();
        st.note_last_write(LastWritePhases {
            n_blocks: 2,
            wall_ns: 3_000_000,
            class_a_ns: 500_000,
            ensure_ns: 50_000,
            structural_ns: 1_000_000,
            spent_ns: 100_000,
            create_h_ns: 200_000,
            bip68_ns: 50_000,
            class_c_ns: 400_000,
            spend_ann_ns: 300_000,
            tweak_ns: 2_500_000,
        });
        let p = st.last_write_phases();
        assert_eq!(p.n_blocks, 2);
        assert_eq!(LastWritePhases::ms(p.wall_ns), 3);
        assert_eq!(LastWritePhases::ms(p.class_a_ns), 0);
        assert_eq!(p.class_a_ns, 500_000);
        assert_eq!(p.tweak_ns, 2_500_000);
        assert_eq!(LastWritePhases::ms(p.tweak_ns), 2);
        st.tweak_ns.store(42, Ordering::Relaxed);
        assert_eq!(st.tweak_ns.swap(0, Ordering::Relaxed), 42);
        assert_eq!(st.tweak_ns.swap(0, Ordering::Relaxed), 0);
        note_confirm(&st.write_plan_take_ns, 11);
        note_confirm(&st.write_create_map_ns, 22);
        note_confirm(&st.write_head_sub_ns, 33);
        let w = st.take_window();
        assert_eq!(
            (
                w.write_plan_take_ns,
                w.write_create_map_ns,
                w.write_head_sub_ns
            ),
            (11, 22, 33)
        );
        assert_eq!(st.take_window().write_plan_take_ns, 0);
        st.connect_ns.store(1, Ordering::Relaxed);
        st.script_ns.store(1, Ordering::Relaxed);
        st.class_a_ns.store(9, Ordering::Relaxed);
        st.ensure_layout_ns.store(11, Ordering::Relaxed);
        st.phase_prep_wire_arc_ns.store(3, Ordering::Relaxed);
        st.asm_prevout_ns.store(10, Ordering::Relaxed);
        st.asm_in_n.store(100, Ordering::Relaxed);
        st.ensure_res_hit.store(8, Ordering::Relaxed);
        let w = st.take_window();
        assert_eq!(w.connect_ns, 1);
        assert_eq!(w.script_ns, 1);
        assert_eq!(w.class_a_ns, 9);
        assert_eq!(w.ensure_layout_ns, 11);
        assert_eq!(w.phase_prep_wire_arc_ns, 3);
        assert_eq!(w.asm_prevout_ns, 10);
        assert_eq!(w.asm_in_n, 100);
        assert_eq!(w.ensure_res_hit, 8);
        assert_eq!(st.take_window().connect_ns, 0);
    }

    #[test]
    fn verify_tx_scripts_detached_acs_job() {
        let tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([1; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let prevouts = vec![TxOut {
            value: Amount::from_sat(10),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }];
        crate::verify_tx_scripts_detached(prevouts.clone(), tx.clone()).unwrap();
        let job = ScriptCheckJob::new(
            prevouts,
            tx,
            crate::block::ScriptVerifyFlags::buried(true, true, true, true, true),
        );
        crate::block::verify_one_script_job(&job).unwrap();
    }

    #[test]
    fn verify_tx_scripts_detached_forks_op_true_and_op_return() {
        let spend = |spk: Vec<u8>| {
            let tx = Transaction {
                version: TxVersion::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::from_byte_array([1; 32]),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            };
            let prevouts = vec![TxOut {
                value: Amount::from_sat(10),
                script_pubkey: ScriptBuf::from_bytes(spk),
            }];
            crate::verify_tx_scripts_detached_forks(prevouts, tx, true, true, true, true, true)
        };
        spend(vec![0x51]).unwrap();
        assert!(spend(vec![0x6a]).is_err());
    }

    #[test]
    fn regtest_connect_archive_and_confirm_path() {
        let (path, q) = temp_store();
        let params = ChainParams::regtest();
        let ms = Milestone { height: 1_000_000 };
        let genesis = genesis_block(&params);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();

        let b1 = mine_regtest(genesis.block_hash(), genesis.header.time + 600, 1, vec![]);
        // prepare helpers stay (CPU-side); confirm is sole Class A.
        let (_hr, _txs) = prepare_block_for_archive(&q, &params, &b1).unwrap();
        let (_hr2, _txs2) = prepare_block_for_archive_new(&q, &params, &b1).unwrap();
        accept_and_connect_block(&q, &params, Height(1), &b1, ms).unwrap();
        // already-have prepare after connect
        let _ = prepare_block_for_archive(&q, &params, &b1).unwrap();

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn assemble_second_block_rejects_stale_nversion() {
        let (path, q) = temp_store();
        let params = ChainParams::regtest();
        let ms = Milestone { height: 1_000_000 };
        let genesis = genesis_block(&params);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();

        let b1 = mine_regtest(genesis.block_hash(), genesis.header.time + 600, 1, vec![]);
        let mut b2 = mine_regtest(b1.block_hash(), b1.header.time + 600, 2, vec![]);
        b2.header.version = Version::from_consensus(1);
        let target = Target::from_compact(b2.header.bits);
        for nonce in 0..u32::MAX {
            b2.header.nonce = nonce;
            if b2.header.validate_pow(target).is_ok() {
                break;
            }
        }
        let err =
            confirm_wire_run(&q, &params, ms, &[(Height(1), b1), (Height(2), b2)]).unwrap_err();
        assert!(matches!(err, ConsensusError::BadVersion(1)), "{err:?}");
        let _ = std::fs::remove_dir_all(&path);
    }
}
