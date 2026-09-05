//! Combined archive-prep + confirm-load stage (single parent-body path).
//!
//! Production confirm load calls [`load_creates_once`] for Class A create decode
//! and pin_new denserels. Always idx→body with `range=None` (no process pin FIFO).
//! Pipeline pins live on the plan (`batch_pin`, `BatchParents`); ancient
//! parents use cold Class A by stamped range.

use rbitcoin_primitives::Fk;
use rbitcoin_store::{
    decode_packed_tx_outs_with_spender_rels_secret, decode_packed_tx_with_spender_rels_secret,
    IdxBodyJob, IdxBodyMode, Store, StoreError, StoreSecret,
};
#[cfg(debug_assertions)]
mod body_ok_spy {
    use std::cell::Cell;
    thread_local! {
        static BODY_OK_READS: Cell<u64> = const { Cell::new(0) };
    }
    pub fn reset_body_ok_reads() {
        BODY_OK_READS.with(|c| c.set(0));
    }
    pub fn body_ok_reads() -> u64 {
        BODY_OK_READS.with(|c| c.get())
    }
    pub fn note() {
        BODY_OK_READS.with(|c| c.set(c.get().saturating_add(1)));
    }
}

#[cfg(debug_assertions)]
pub use body_ok_spy::{body_ok_reads, reset_body_ok_reads};

#[inline]
fn note_body_ok_read() {
    #[cfg(debug_assertions)]
    body_ok_spy::note();
}

/// One create loaded for the combined path.
#[derive(Debug, Clone)]
pub struct CombinedCreate {
    pub fk: Fk,
    pub body_range: (u64, u64),
    pub raw: Vec<u8>,
    /// When `mode == Full`, one full decode lives here so callers do not re-decode.
    pub decoded_full: Option<(
        rbitcoin_store::TxRecord,
        Vec<rbitcoin_store::InputRecord>,
        Vec<rbitcoin_store::OutputRecord>,
        Vec<u32>,
    )>,
    /// When `mode == OutsDenserels`, decoded meta/outs/denserels (avoid re-decode on pin).
    pub decoded_outs: Option<(
        rbitcoin_store::TxRecord,
        Vec<rbitcoin_store::OutputRecord>,
        Vec<u32>,
    )>,
}

/// Load creates by fk via idx→body, decode once.
///
/// Each successful body fetch increments [`body_ok_reads`]. Ranges are always
/// resolved from `tx.idx` (`range=None` on jobs). Callers fill schema-13 zero
/// body `TxRecord.txid` from plan RAM maps when needed — this path never seeds
/// a process pin map and does not fill txid from `txid.body` for that purpose.
///
/// **Shipped entry used by** wire pin and SH.
pub fn load_creates_once(
    store: &Store,
    fks: &[Fk],
    mode: IdxBodyMode,
) -> Result<Vec<CombinedCreate>, rbitcoin_store::StoreError> {
    if fks.is_empty() {
        return Ok(Vec::new());
    }
    let mut jobs: Vec<IdxBodyJob> = fks
        .iter()
        .map(|fk| IdxBodyJob::new(fk.get().unwrap_or(0), None))
        .collect();
    store.idx_body_pipeline(&mut jobs, mode)?;
    let mut inwit_jobs: Vec<IdxBodyJob> = if mode == IdxBodyMode::Full {
        fks.iter()
            .map(|fk| IdxBodyJob::new(fk.get().unwrap_or(0), None))
            .collect()
    } else {
        Vec::new()
    };
    if mode == IdxBodyMode::Full {
        store.idx_inwit_pipeline(&mut inwit_jobs, IdxBodyMode::Full)?;
    }
    let secret: &StoreSecret = store.txs.store_secret();
    let mut out = Vec::with_capacity(jobs.len());
    for (i, (fk, job)) in fks.iter().zip(jobs.into_iter()).enumerate() {
        if !job.ok {
            continue;
        }
        let Some(range) = job.range else {
            continue;
        };
        note_body_ok_read();
        let mut decoded_full = None;
        let mut decoded_outs = None;
        match mode {
            IdxBodyMode::Full => {
                if let Ok((tx, _empty_ins, outs, rels)) =
                    decode_packed_tx_with_spender_rels_secret(&job.body, Some(secret))
                {
                    let Some(ij) = inwit_jobs.get(i) else {
                        return Err(StoreError::Corrupt(
                            "invariant: Full create missing inwit job",
                        ));
                    };
                    if !ij.ok {
                        return Err(StoreError::Corrupt(
                            "invariant: Full create inwit body missing after load",
                        ));
                    }
                    let ins =
                        rbitcoin_store::decode_inwit_secret(&ij.body, tx.input_count, Some(secret))
                            .map_err(|_| {
                                StoreError::Corrupt("invariant: packed create inwit decode failed")
                            })?;
                    decoded_full = Some((tx, ins, outs, rels));
                } else {
                    return Err(StoreError::Corrupt(
                        "invariant: packed create Full decode failed after body load",
                    ));
                }
            }
            IdxBodyMode::Outs | IdxBodyMode::Prefix33 => {
                if let Ok((tx, outs, rels)) =
                    decode_packed_tx_outs_with_spender_rels_secret(&job.body, Some(secret))
                {
                    // Leave txid zero; caller fills from plan
                    // `external_parents` / batch maps only.
                    decoded_outs = Some((tx, outs, rels));
                } else {
                    return Err(StoreError::Corrupt(
                        "invariant: packed create denserels decode failed after body load",
                    ));
                }
            }
        }
        out.push(CombinedCreate {
            fk: *fk,
            body_range: range,
            raw: job.body,
            decoded_full,
            decoded_outs,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Query;
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    fn temp_query() -> (std::path::PathBuf, Query) {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, AtomicOrdering::Relaxed);
        let dir = std::env::temp_dir().join(format!("rbitcoin-combined-q-{id}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(dir.join("store")).unwrap();
        (dir, q)
    }

    fn put_tx(q: &Query, seed: u8) -> Fk {
        let mut txid = [0u8; 32];
        txid[0] = seed;
        let tx = TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 2,
        };
        let inputs = vec![InputRecord::coinbase(u32::MAX, vec![0x01, seed], vec![])];
        let outs = vec![
            OutputRecord::unspent(10, vec![0x76, 0xa9, seed]),
            OutputRecord::unspent(20, vec![0x51]),
        ];
        q.store()
            .txs
            .put_full_batch_indexed(&[(tx, inputs, outs)], true)
            .unwrap()[0]
    }

    /// Drive shipped `load_creates_once` (wire pin + SH).
    #[test]
    fn load_creates_once_combined_body_path() {
        let (dir, q) = temp_query();
        let fks: Vec<Fk> = (0..4u8).map(|i| put_tx(&q, i + 20)).collect();
        reset_body_ok_reads();
        let creates = load_creates_once(q.store(), &fks, IdxBodyMode::Full).unwrap();
        assert_eq!(creates.len(), fks.len());
        assert!(body_ok_reads() >= 1, "combined path must body-fetch");
        // Schema 13: identity lives in txid.body / plan RAM, not body prefix.
        let c = &creates[0];
        let t = c
            .decoded_full
            .as_ref()
            .map(|(tx, _, _, _)| tx.txid)
            .unwrap_or([0u8; 32]);
        // Full decode leaves zero unless filled; sidefile holds identity.
        let tid = if t == [0u8; 32] {
            q.store().txs.body_txid(c.fk).unwrap()
        } else {
            t
        };
        assert_ne!(tid, [0u8; 32], "sidefile must supply identity");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// OutsDenserels parent path returns denserels decode without process pins.
    #[test]
    fn outs_denserels_loads_parent_decode() {
        let (dir, q) = temp_query();
        let fk = put_tx(&q, 7);
        let creates = load_creates_once(q.store(), &[fk], IdxBodyMode::Outs).unwrap();
        assert_eq!(creates.len(), 1);
        assert!(
            creates[0].decoded_outs.is_some(),
            "decode must succeed for pin"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn block_queue_via_query_enqueue_reopen_empty() {
        let (dir, q) = temp_query();
        let payload = b"ibd-block-payload-bytes".to_vec();
        let id = q
            .block_queue_enqueue(42, [0xCDu8; 32], 7, &payload)
            .unwrap();
        assert_eq!(q.block_queue_stats().2, 1);
        let _ = id;
        assert!(q.block_queue_has_height(42));
        assert_eq!(
            q.block_queue_payload(42).unwrap().as_deref(),
            Some(payload.as_slice())
        );
        // Confirm-write hook: dequeue by height.
        assert_eq!(q.block_queue_dequeue_height(42).unwrap(), 1);
        assert_eq!(q.block_queue_stats().2, 0);
        // Restart: RAM queue is empty (by design — redownload, no double disk write).
        drop(q);
        let q2 = Query::open_or_create(dir.join("store")).unwrap();
        assert!(!q2.block_queue_has_height(42));
        assert_eq!(q2.block_queue_stats().2, 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Offer always lands in the process-local RAM queue.
    #[test]
    fn block_queue_offer_always_ram() {
        let (dir, q) = temp_query();
        let p1 = vec![1u8; 64 * 1024];
        let p2 = vec![2u8; 64 * 1024];
        let o1 = q.block_queue_offer(1, [1u8; 32], 1, &p1).unwrap();
        assert!(o1.queue_id > 0);
        assert_eq!(q.block_queue_stats().2, 1);
        let o2 = q.block_queue_offer(2, [2u8; 32], 2, &p2).unwrap();
        assert!(o2.queue_id > 0);
        assert_eq!(q.block_queue_stats().2, 2);
        let n = q.block_queue_dequeue_height(1).unwrap();
        assert_eq!(n, 1);
        assert_eq!(q.block_queue_stats().2, 1);
        assert!(q.block_queue_has_height(2));
        assert!(!q.block_queue_has_height(1));
        assert_eq!(
            q.block_queue_payload(2).unwrap().as_deref(),
            Some(p2.as_slice())
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Confirm load intake: payload by height from RAM (no dequeue).
    #[test]
    fn block_queue_payload_peek_ram() {
        let (dir, q) = temp_query();
        let wire = b"ram-payload".to_vec();
        q.block_queue_enqueue(10, [0xAAu8; 32], 1, &wire).unwrap();
        assert_eq!(
            q.block_queue_payload(10).unwrap().as_deref(),
            Some(wire.as_slice())
        );
        assert!(q.block_queue_has_height(10));
        assert_eq!(q.block_queue_stats().2, 1, "peek does not dequeue");
        assert!(q.block_queue_payload(999).unwrap().is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn block_queue_soft_free_bytes_and_confirm_window() {
        use crate::{
            soft_assign_restricted, soft_confirm_window_covered, soft_confirm_window_n,
            soft_densify_band_hi, BQ_SOFT_CONFIRM_SECS, BQ_SOFT_FREE_BYTES,
        };
        // 5 blk/s × 60s → window 300.
        assert_eq!(soft_confirm_window_n(Some(5.0)), 300);
        assert_eq!(soft_confirm_window_n(None), 0);
        assert_eq!(
            soft_confirm_window_n(Some(2.0)),
            (2.0 * BQ_SOFT_CONFIRM_SECS).ceil() as u32
        );

        let free = BQ_SOFT_FREE_BYTES;
        let over = free + 1;
        // Under free: full densify_hi regardless of rate.
        assert_eq!(
            soft_densify_band_hi(100, 1000, free, Some(0.1), u64::MAX, None),
            1000
        );
        assert!(!soft_assign_restricted(free));
        // densify_hi < path_lo edge (empty band).
        assert_eq!(
            soft_densify_band_hi(50, 40, free, Some(1.0), u64::MAX, None),
            40
        );
        assert_eq!(
            soft_densify_band_hi(50, 40, over, Some(1.0), u64::MAX, None),
            40
        );
        // Over free: confirm window only.
        assert_eq!(
            soft_densify_band_hi(100, 1000, over, Some(0.1), u64::MAX, None),
            105,
            "0.1 blk/s × 60s = 6 heights → path_lo..path_lo+5"
        );
        assert_eq!(
            soft_densify_band_hi(100, 1000, over, None, u64::MAX, None),
            100,
            "rate cold → tip-adjacent only"
        );
        // Window clamp to densify_hi when rate is high.
        assert_eq!(
            soft_densify_band_hi(100, 110, over, Some(5.0), u64::MAX, None),
            110,
            "window 300 clamped to densify_hi=110"
        );
        assert!(soft_assign_restricted(over));
        assert!(!soft_confirm_window_covered(50, over, Some(5.0))); // 50 < 300
        assert!(soft_confirm_window_covered(300, over, Some(5.0)));
        assert!(soft_confirm_window_covered(1, over, None)); // cold + over free
        assert!(!soft_confirm_window_covered(1, free, None)); // under free never covered

        let (dir, q) = temp_query();
        assert!(!q.block_queue_update_soft_pressure(Some(5.0)));
        // Many tiny payloads — under free floor, unrestricted.
        for i in 0..451u32 {
            q.block_queue_enqueue(
                i,
                {
                    let mut h = [0u8; 32];
                    h[..4].copy_from_slice(&i.to_le_bytes());
                    h
                },
                1,
                b"x",
            )
            .unwrap();
        }
        assert!(
            !q.block_queue_update_soft_pressure(Some(5.0)),
            "early-chain style: many tiny blocks under free-byte floor"
        );
        // Two ~80 MiB payloads → over free floor → restricted.
        for i in 0..451u32 {
            let _ = q.block_queue_dequeue_height(i);
        }
        let chunk = vec![0u8; 80 * 1024 * 1024];
        q.block_queue_enqueue(1, [1u8; 32], 1, &chunk).unwrap();
        q.block_queue_enqueue(2, [2u8; 32], 2, &chunk).unwrap();
        assert!(q.block_queue_stats().1 > BQ_SOFT_FREE_BYTES);
        assert!(
            q.block_queue_update_soft_pressure(None),
            "bytes over free floor → restricted"
        );
        // Drop one chunk → under free floor → unrestricted.
        q.block_queue_dequeue_height(1).unwrap();
        assert!(q.block_queue_stats().1 < BQ_SOFT_FREE_BYTES);
        assert!(
            !q.block_queue_update_soft_pressure(None),
            "bytes under free floor → unrestricted"
        );

        // Soft restriction must never block peer offer / enqueue (request-limited only).
        let chunk2 = vec![0u8; 80 * 1024 * 1024];
        q.block_queue_enqueue(3, [3u8; 32], 3, &chunk2).unwrap();
        q.block_queue_enqueue(4, [4u8; 32], 4, &chunk2).unwrap();
        assert!(
            q.block_queue_update_soft_pressure(None),
            "re-enter restricted for offer regression"
        );
        assert!(q.block_queue_soft_pressure());
        let offered = q
            .block_queue_offer(5, [5u8; 32], 5, b"already-requested-body")
            .expect("offer must succeed while soft densify is restricted");
        assert!(offered.queue_id > 0);
        assert!(q.block_queue_has_height(5));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn block_queue_promote_marks_resolve_and_omits_missing() {
        use crate::ResolvedWire;
        use bitcoin::block::{Header, Version};
        use bitcoin::hashes::Hash;
        use bitcoin::{Block, BlockHash, CompactTarget, TxMerkleNode};
        use std::sync::Arc;

        let (dir, q) = temp_query();
        q.block_queue_enqueue(7, [7u8; 32], 1, b"wire-7").unwrap();
        q.block_queue_enqueue(8, [8u8; 32], 2, b"wire-8").unwrap();
        let block = Block {
            header: Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::from_byte_array([0; 32]),
                merkle_root: TxMerkleNode::from_byte_array([0; 32]),
                time: 1,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            },
            txdata: vec![],
        };
        let wire = ResolvedWire {
            block: Arc::new(block),
            pres: Arc::from(Vec::new()),
        };
        q.block_queue_promote_wave(vec![(7, wire, 64)]).unwrap();
        q.block_queue_mark_resolve_complete(7).unwrap();
        assert!(q.block_queue_is_resolve_complete(7));
        assert!(q.block_queue_resolved(7).is_some());
        assert_eq!(q.block_queue_hash_at_height(7), Some([7u8; 32]));
        assert!(q.block_queue_has_height(8));
        assert!(!q.block_queue_is_resolve_complete(8));
        assert!(q.block_queue_resolved(8).is_none());
        assert!(!q.block_queue_has_height(9));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn block_queue_unresolved_heights_via_query() {
        use std::collections::HashSet;
        let (dir, q) = temp_query();
        for h in 10..18u32 {
            q.block_queue_enqueue(h, [h as u8; 32], 1, b"w").unwrap();
        }
        q.block_queue_mark_resolve_complete(10).unwrap();
        q.block_queue_mark_resolve_complete(11).unwrap();
        let skip: HashSet<u32> = [12].into_iter().collect();
        let got = q.block_queue_unresolved_heights(10, &skip, 8);
        assert_eq!(got, vec![13, 14, 15, 16, 17]);
        assert_eq!(q.block_queue_unresolved_heights(10, &skip, 2), vec![13, 14]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unresolved_heights_walks_past_taken_bq_hole() {
        use std::collections::HashSet;
        let (dir, q) = temp_query();
        for h in 10..20u32 {
            q.block_queue_enqueue(h, [h as u8; 32], 1, b"w").unwrap();
        }
        for h in 10..=12u32 {
            assert!(q.block_queue_take_raw(h).is_some());
        }
        q.set_lookup_taken_hi(Some(12));
        let none = HashSet::new();
        assert_eq!(
            q.block_queue_unresolved_heights(10, &none, 8),
            vec![13, 14, 15, 16, 17, 18, 19]
        );
        assert!(q.block_queue_take_raw(15).is_some());
        assert_eq!(q.block_queue_unresolved_heights(10, &none, 8), vec![13, 14]);
        assert_eq!(
            q.block_queue_unresolved_heights(16, &none, 8),
            vec![16, 17, 18, 19]
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn lookup_take_removes_bq_row_via_query() {
        let (dir, q) = temp_query();
        q.block_queue_enqueue(3, [3u8; 32], 1, b"xyz").unwrap();
        assert!(q.block_queue_has_height(3));
        let got = q.block_queue_take_raw(3).expect("take");
        assert_eq!(got.payload, b"xyz");
        assert!(!q.block_queue_has_height(3));
        assert!(q.block_queue_take_raw(3).is_none());
        assert!(!q.lookup_already_taken(3));
        q.set_lookup_taken_hi(Some(3));
        assert!(q.lookup_already_taken(3));
        assert!(q.lookup_already_taken(2));
        assert!(!q.lookup_already_taken(4));
        q.set_lookup_taken_hi(None);
        assert!(!q.lookup_already_taken(3));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn wave_intake_does_not_clone_raw_for_asked_set() {
        let (dir, q) = temp_query();
        for h in 0..64u32 {
            q.block_queue_enqueue(h, [h as u8; 32], 1, &[h as u8; 64])
                .unwrap();
        }
        let asked: Vec<u32> = (0..64).collect();
        let _ = rbitcoin_store::take_raw_clone_n();
        let intake = q.block_queue_wave_intake(&asked);
        assert_eq!(intake.raw.len(), 64, "all still-raw heights classified");
        assert_eq!(
            rbitcoin_store::take_raw_clone_n(),
            0,
            "wave_intake must not clone raw payloads for the asked set"
        );
        for &h in asked.iter().take(16) {
            assert!(q.block_queue_raw_payload(h).unwrap().is_some());
        }
        assert_eq!(
            rbitcoin_store::take_raw_clone_n(),
            16,
            "only the decode prefix may clone"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn block_queue_promote_wave_keeps_resolved_drops_raw() {
        use crate::ResolvedWire;
        use bitcoin::block::{Header, Version};
        use bitcoin::hashes::Hash;
        use bitcoin::{Block, BlockHash, CompactTarget, TxMerkleNode};
        use std::sync::Arc;

        let (dir, q) = temp_query();
        q.block_queue_enqueue(7, [7u8; 32], 1, b"wire-7").unwrap();
        q.block_queue_enqueue(8, [8u8; 32], 2, b"wire-8").unwrap();
        let block = Block {
            header: Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::from_byte_array([0; 32]),
                merkle_root: TxMerkleNode::from_byte_array([0; 32]),
                time: 1,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            },
            txdata: vec![],
        };
        let wire = ResolvedWire {
            block: Arc::new(block),
            pres: Arc::from(Vec::new()),
        };
        let intake = q.block_queue_wave_intake(&[7, 8]);
        assert_eq!(intake.raw.len(), 2);
        assert!(intake.resolved.is_empty());
        q.block_queue_promote_wave(vec![(7, wire.clone(), 64)])
            .unwrap();
        assert!(q.block_queue_raw_payload(7).unwrap().is_none());
        assert!(q.block_queue_payload(7).unwrap().unwrap().is_empty());
        assert_eq!(
            q.block_queue_stats().1,
            64 + 6,
            "charge 64 + leftover raw wire-8"
        );
        let got = q.block_queue_resolved(7).expect("resolved");
        assert_eq!(got.block.header.time, 1);
        let intake2 = q.block_queue_wave_intake(&[7, 8]);
        assert_eq!(intake2.resolved.len(), 1);
        assert_eq!(intake2.raw.len(), 1);
        assert_eq!(intake2.raw[0], (8, 0));
        q.block_queue_drop_resolved_from(7);
        assert!(q.block_queue_resolved(7).is_none());
        assert_eq!(q.block_queue_dequeue_height(8).unwrap(), 1);
        assert!(q.block_queue_resolved(8).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn obfuscation_on_disk_via_store_put() {
        let (dir, q) = temp_query();
        let script = vec![0x76, 0xa9, 0x14, 0x11, 0x22, 0x33];
        let mut txid = [0u8; 32];
        txid[0] = 0xee;
        let tx = TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        };
        let inputs = vec![InputRecord::coinbase(
            u32::MAX,
            script.clone(),
            vec![vec![9]],
        )];
        let outs = vec![OutputRecord::unspent(1, script.clone())];
        let mut plain = Vec::new();
        rbitcoin_store::encode_packed_tx_with_secret(&tx, &inputs, &outs, &mut plain, None);
        let mut obf = Vec::new();
        rbitcoin_store::encode_packed_tx_with_secret(
            &tx,
            &inputs,
            &outs,
            &mut obf,
            Some(q.store().txs.store_secret()),
        );
        assert_ne!(plain, obf);
        let fk = q
            .store()
            .txs
            .put_full_batch_indexed(&[(tx, inputs, outs)], true)
            .unwrap()[0];
        reset_body_ok_reads();
        let creates = load_creates_once(q.store(), &[fk], IdxBodyMode::Full).unwrap();
        assert_eq!(creates.len(), 1);
        assert!(
            !creates[0]
                .raw
                .windows(script.len())
                .any(|w| w == script.as_slice()),
            "plaintext script must not appear on disk"
        );
        let (_dtx, _ins, douts, _) = decode_packed_tx_with_spender_rels_secret(
            &creates[0].raw,
            Some(q.store().txs.store_secret()),
        )
        .unwrap();
        assert_eq!(douts[0].script, script);
        let _ = std::fs::remove_dir_all(dir);
    }
}
