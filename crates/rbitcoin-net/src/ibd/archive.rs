//! Body-queue rehydrate into confirm after restart.
//!
//! Dual-track archive-job Class A pipeline was removed — confirm is sole Class A.
//! After restart the RAM body queue is empty; Class A bodies on the tip path are
//! reconstructed into the queue so confirm can claim without re-getdata.

use crate::chain::ChainHub;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rbitcoin_primitives::Fk;

use std::time::Instant;

pub(crate) fn rehydrate_block_queue_into_confirm(
    hub: &ChainHub,
    st: &mut super::state::IbdWorkState,
    confirm_feed: &super::confirm::ConfirmFeed,
) -> Result<usize, String> {
    use rbitcoin_log::{info, warn};

    let tip_opt = hub.tip_height();
    let path_lo = match tip_opt {
        None => 0u32,
        Some(t) => t.saturating_add(1),
    };

    // Index only. After restart the RAM queue is empty (by design — sole durable
    // write is Class A; redownload instead of double disk write). Same-process
    // residual still notes feed readiness.
    let queued = hub.query.block_queue_list_meta();
    if queued.is_empty() {
        return Ok(0);
    }
    let mut n = 0usize;
    let mut bytes = 0u64;
    let mut h_min = u32::MAX;
    let mut h_max = 0u32;
    let mut dropped_done = 0usize;
    let mut empty_skip = 0usize;
    let mut unknown_h = 0usize;
    let mut kept_above_tip_flag = 0usize;
    for qb in queued {
        let hash = BlockHash::from_byte_array(qb.hash);
        // Only drop residue at/below confirmed tip (write may have missed dequeue).
        // Heights above tip always keep wire — even if has_block/known looks set
        // (stale RAM or Class A ahead of tip must not erase confirm payload).
        // No tip yet → keep every height (including 0).
        let at_or_below_tip = match tip_opt {
            Some(tip) if qb.height != u32::MAX && qb.height <= tip => true,
            _ => false,
        };
        if at_or_below_tip {
            let _ = hub.query.block_queue_dequeue_height(qb.height);
            dropped_done = dropped_done.saturating_add(1);
            continue;
        }
        if hub.has_block(&hash) || st.body.is_known_archived(&hash) {
            kept_above_tip_flag = kept_above_tip_flag.saturating_add(1);
        }
        if qb.payload_len == 0 {
            empty_skip = empty_skip.saturating_add(1);
            let _ = hub.query.block_queue_dequeue_height(qb.height);
            continue;
        }
        let wire_bytes = qb.payload_len;
        st.body.mark_pending(hash);
        if qb.height != u32::MAX {
            st.record_height(hash, qb.height);
        }
        let header_fk = Fk(qb.header_fk);
        if !header_fk.is_null() {
            st.header_fks.insert(hash, header_fk);
        }
        if qb.height != u32::MAX {
            confirm_feed.note(qb.height, hash);
            bytes = bytes.saturating_add(wire_bytes);
            h_min = h_min.min(qb.height);
            h_max = h_max.max(qb.height);
            n = n.saturating_add(1);
        } else {
            st.body.mark_missing(hash);
            unknown_h = unknown_h.saturating_add(1);
        }
    }

    // Tip+1..bq_min gap: wire was dequeued/never filled while tip lagged → densify.
    // Skip only **claim-ready** heights (confirmed / pending / BQ). Class A alone
    // (resume seed `mark_archived`) is not claimable — still mark_missing so
    // tip-hole race / densify re-getdata into the body queue.
    let mut gap_marked = 0u32;
    if n > 0 && h_min > path_lo {
        for ht in path_lo..h_min {
            let Some(&hash) = st.height_to_hash.get(&ht) else {
                continue;
            };
            if hub.has_block(&hash)
                || st.body.is_pending(&hash)
                || hub.query.block_queue_has_height(ht)
            {
                continue;
            }
            st.body.mark_missing(hash);
            gap_marked = gap_marked.saturating_add(1);
        }
        if gap_marked > 0 {
            warn!(
                "ibd: body queue gap tip+1={path_lo}..{} (bq starts {h_min}) — \
                 marked {gap_marked} missing for densify re-getdata",
                h_min.saturating_sub(1)
            );
        }
    }

    if n > 0 || dropped_done > 0 || empty_skip > 0 || unknown_h > 0 || gap_marked > 0 {
        let mib = bytes / (1024 * 1024);
        if n > 0 {
            info!(
                "ibd: rehydrate body queue → feed ready n={n} h={h_min}..{h_max} \
                 {mib}MiB (dropped_le_tip={dropped_done} empty={empty_skip} unknown_h={unknown_h} \
                 gap_marked={gap_marked} kept_above_tip_flag={kept_above_tip_flag})"
            );
        } else {
            info!(
                "ibd: rehydrate body queue: no ready entries \
                 (dropped_le_tip={dropped_done} empty={empty_skip} unknown_h={unknown_h} \
                 gap_marked={gap_marked})"
            );
        }
        if empty_skip > 0 {
            warn!("ibd: rehydrate dropped {empty_skip} empty body-queue rec(s)");
        }
    }
    Ok(n)
}

/// Reconstruct Class A bodies from tip+1 into the RAM body queue (restart path).
///
/// Body queue is RAM-only (no durable wire). Resume seed marks Class A as known
/// for densify bookkeeping, but confirm intake is **BQ wire only**. Prefer
/// Class A reconstruct → `block_queue_offer` over peer re-getdata for the tip
/// confirm batch (`max`, typically [`super::TIP_HOLE_MAX`]).
///
/// Walks **contiguous** heights from tip+1: stops at the first height without
/// Class A (or reconstruct/offer failure → mark_missing so assign re-gets).
/// Already-queued / pending / confirmed heights are skipped without breaking
/// the contiguous walk when still claim-ready.
pub(crate) fn rehydrate_class_a_into_body_queue(
    hub: &ChainHub,
    st: &mut super::state::IbdWorkState,
    confirm_feed: &super::confirm::ConfirmFeed,
    max: usize,
) -> Result<usize, String> {
    use rbitcoin_log::{info, warn};

    if max == 0 {
        return Ok(0);
    }
    let path_lo = match hub.tip_height() {
        None => 0u32,
        Some(t) => t.saturating_add(1),
    };
    let t0 = Instant::now();
    let mut n = 0usize;
    let mut bytes = 0u64;
    let mut h_min = u32::MAX;
    let mut h_max = 0u32;
    let mut failed = 0u32;

    for ht in path_lo.. {
        if n >= max {
            break;
        }
        let Some(&hash) = st.height_to_hash.get(&ht) else {
            break;
        };
        if hub.has_block(&hash) {
            // Confirmed-set contains this hash. If that is tip+1 while tip is
            // still lower, confirmed[] stole the tip+1 row (mainnet stall:
            // conf[mid]=tip+1 → has_block true → never rehydrate/offer tip+1).
            if ht == path_lo && hub.tip_height().is_some() {
                warn!(
                    "ibd: tip+1={ht} {hash} is in confirmed-set while tip={} — \
                     confirmed[] likely maps an earlier height to tip+1; \
                     restart after tip revalidate / open repair (or fresh datadir)",
                    hub.tip_height().unwrap_or(0)
                );
            }
            break;
        }
        if st.body.is_rejected(&hash) {
            break;
        }
        if hub.query.block_queue_has_height(ht) {
            st.body.mark_pending(hash);
            confirm_feed.note(ht, hash);
            n = n.saturating_add(1);
            h_min = h_min.min(ht);
            h_max = h_max.max(ht);
            continue;
        }
        if st.body.is_pending(&hash) {
            st.body.mark_missing(hash);
        }
        let has_class_a = st.body.is_known_archived(&hash)
            || hub
                .query
                .is_block_archived(&hash.to_byte_array())
                .unwrap_or(false);
        if !has_class_a {
            break;
        }

        let block = match hub.query.reconstruct_archived_block(&hash.to_byte_array()) {
            Ok(Some(b)) => b,
            Ok(None) => {
                warn!(
                    "ibd: Class A rehydrate h={ht}: header_txs missing after archive flag — re-getdata"
                );
                st.body.mark_missing(hash);
                failed = failed.saturating_add(1);
                break;
            }
            Err(e) => {
                warn!("ibd: Class A rehydrate reconstruct h={ht} {hash}: {e} — re-getdata");
                st.body.mark_missing(hash);
                failed = failed.saturating_add(1);
                break;
            }
        };

        // Corrupt Class A (wrong txs linked to header) — do not feed confirm.
        // Clear association so densify re-getdatas; never permanent-blacklist.
        let merkle_ok = block
            .compute_merkle_root()
            .is_some_and(|mr| mr == block.header.merkle_root);
        if !merkle_ok || block.block_hash() != hash {
            warn!(
                "ibd: Class A rehydrate h={ht} {hash}: reconstructed body fails header check \
                 (merkle/hash) — clear Class A and re-getdata"
            );
            let _ = hub.query.clear_archived_body(hash.as_byte_array());
            st.body.demote_known(hash);
            st.body.mark_missing(hash);
            failed = failed.saturating_add(1);
            break;
        }

        let mut payload = Vec::new();
        if block.consensus_encode(&mut payload).is_err() {
            warn!("ibd: Class A rehydrate encode h={ht} {hash} failed — re-getdata");
            st.body.mark_missing(hash);
            failed = failed.saturating_add(1);
            break;
        }
        let header_fk = st.header_fks.get(&hash).copied().unwrap_or(Fk::NULL);
        match hub
            .query
            .block_queue_offer(ht, hash.to_byte_array(), header_fk.0, &payload)
        {
            Ok(_) => {}
            Err(e) => {
                warn!("ibd: Class A rehydrate offer h={ht}: {e} — re-getdata");
                st.body.mark_missing(hash);
                failed = failed.saturating_add(1);
                break;
            }
        }
        st.body.mark_pending(hash);
        // Keep known_archived for densify skip of far Class A; pending is claim-ready.
        confirm_feed.note(ht, hash);
        st.max_ready_height = st.max_ready_height.max(ht);
        bytes = bytes.saturating_add(payload.len() as u64);
        h_min = h_min.min(ht);
        h_max = h_max.max(ht);
        n = n.saturating_add(1);
    }

    if n > 0 || failed > 0 {
        let mib = bytes / (1024 * 1024);
        info!(
            "ibd: Class A rehydrate → body queue n={n} h={h_min}..{h_max} \
             {mib}MiB fail={failed} (store reconstruct {:?})",
            t0.elapsed()
        );
    }
    Ok(n)
}

#[cfg(test)]
mod class_a_rehydrate_tests {
    use super::rehydrate_class_a_into_body_queue;
    use crate::ibd::confirm::ConfirmFeed;
    use crate::ibd::progress::claim_ready;
    use crate::ibd::state::IbdWorkState;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, Block, BlockHash, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn,
        TxOut, Witness,
    };
    use rbitcoin_query::testutil::FixtureChain;

    fn mine(prev: BlockHash, time: u32, height: u32) -> Block {
        let mut ss = if height == 0 {
            vec![0x00]
        } else {
            rbitcoin_consensus::bip34_height_script(height)
        };
        while ss.len() < 2 {
            ss.push(0x00);
        }
        let coinbase = Transaction {
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
        };
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let header = Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time,
            bits,
            nonce: 0,
        };
        let mut block = Block {
            header,
            txdata: vec![coinbase],
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
    fn class_a_rehydrate_makes_tip_plus_one_claim_ready() {
        let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("ca-rehydrate");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let time = 1_300_000_000u32;
        let mut tip = gen;
        let mut hashes = Vec::new();
        // Tip stays at genesis; Class A via commit_class_a_only (not public archive_block).
        for h in 1u32..=3 {
            let b = mine(tip, time + h * 600, h);
            hub.ensure_header(&b.header).unwrap();
            let (rec, txs) =
                rbitcoin_consensus::prepare_block_for_archive(&hub.query, &hub.params, &b).unwrap();
            hub.query.commit_class_a_only(&rec, &txs).unwrap();
            hashes.push(b.block_hash());
            tip = b.block_hash();
        }

        let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
        super::super::path::seed_work_path_from_store(&mut st, &hub);
        assert!(
            st.body.is_known_archived(&hashes[0]),
            "seed must mark Class A known"
        );
        assert!(
            !hub.query.block_queue_has_height(1),
            "BQ empty before rehydrate"
        );
        assert!(
            !claim_ready(&hub, &mut st.body, 1, &hashes[0]),
            "Class A alone is not claim-ready"
        );

        let feed = ConfirmFeed::new();
        let n = rehydrate_class_a_into_body_queue(&hub, &mut st, &feed, 32).unwrap();
        assert_eq!(n, 3, "contiguous Class A prefix should all rehydrate");
        for (i, h) in hashes.iter().enumerate() {
            let ht = (i as u32) + 1;
            assert!(
                hub.query.block_queue_has_height(ht),
                "BQ must hold height {ht}"
            );
            assert!(
                st.body.is_pending(h),
                "pending after Class A rehydrate h={ht}"
            );
            assert!(
                claim_ready(&hub, &mut st.body, ht, h),
                "claim_ready after Class A rehydrate h={ht}"
            );
        }
        assert_eq!(feed.size_snap().0, 3);

        // Idempotent: second call counts already-queued as ready, no error.
        let n2 = rehydrate_class_a_into_body_queue(&hub, &mut st, &feed, 32).unwrap();
        assert_eq!(n2, 3);

        let _ = std::fs::remove_dir_all(dir);
    }
}
