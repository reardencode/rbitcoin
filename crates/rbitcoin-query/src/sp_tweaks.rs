//! Thin BIP-352 tweak index: Query join of `sp_tweaks.*` + Class A.

use super::*;
use rbitcoin_store::SpTweaksTable;

/// Eligible tx after thin-index join (P2TR outs only).
#[derive(Clone, Debug)]
pub struct ThinTweakRow {
    pub txid: [u8; 32],
    pub tweak: [u8; 33],
    pub p2tr: Vec<(u32, [u8; 32], u64)>,
}

/// Budgets for [`Query::load_thin_tweaks_range`] (serve-side multi-height wave).
///
/// Cost is eligible txs / Class A body, not height count alone — pair `max_heights`
/// with `max_eligible` so busy post-taproot blocks do not explode RAM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThinTweakRangeLimits {
    /// Cap on contiguous heights in one wave (default 128).
    pub max_heights: u32,
    /// Cap on total eligible txs across the wave (default 8192).
    pub max_eligible: usize,
}

impl Default for ThinTweakRangeLimits {
    fn default() -> Self {
        Self {
            max_heights: 128,
            max_eligible: 8192,
        }
    }
}

fn require_thin_body_range(r: Option<(u64, u64)>) -> Result<(u64, u64), StoreError> {
    match r {
        None => Err(StoreError::Corrupt(
            "invariant: thin tweak eligible body missing",
        )),
        Some((_, 0)) => Err(StoreError::Corrupt(
            "invariant: thin tweak eligible body empty",
        )),
        Some((off, len)) => Ok((off, len)),
    }
}

fn wave_join_is_dense(elig_count: usize, first_id: u64, last_id: u64) -> bool {
    if elig_count == 0 || last_id < first_id {
        return false;
    }
    let Ok(span) = usize::try_from(last_id - first_id + 1) else {
        return false;
    };
    elig_count.saturating_mul(4) >= span
}

fn thin_join_txids_and_ranges(
    store: &Store,
    elig_fks: &[Fk],
) -> Result<(Vec<Option<[u8; 32]>>, Vec<Option<(u64, u64)>>), StoreError> {
    let Some(first_id) = elig_fks.first().and_then(|f| f.get()) else {
        return Err(StoreError::InvalidFk);
    };
    let Some(last_id) = elig_fks.last().and_then(|f| f.get()) else {
        return Err(StoreError::InvalidFk);
    };
    if wave_join_is_dense(elig_fks.len(), first_id, last_id) {
        let all_txids = store.txs.txid_sidefile().get_range(first_id, last_id)?;
        let all_ranges = store.txs.body_ranges(first_id, last_id)?;
        let n = (last_id - first_id + 1) as usize;
        if all_txids.len() != n || all_ranges.len() != n {
            return Err(StoreError::Corrupt(
                "invariant: thin tweak dense join length mismatch",
            ));
        }
        let mut txids = Vec::with_capacity(elig_fks.len());
        let mut ranges = Vec::with_capacity(elig_fks.len());
        for fk in elig_fks {
            let id = fk.get().ok_or(StoreError::InvalidFk)?;
            let i = (id - first_id) as usize;
            if i >= n {
                return Err(StoreError::Corrupt(
                    "invariant: thin tweak dense join fk outside span",
                ));
            }
            txids.push(Some(all_txids[i]));
            ranges.push(Some(all_ranges[i]));
        }
        Ok((txids, ranges))
    } else {
        Ok((
            store.txs.txid_sidefile().get_many(elig_fks)?,
            store.tx_body_range_batch(elig_fks)?,
        ))
    }
}

impl Query {
    pub fn sptweaks_enabled(&self) -> bool {
        self.sptweaks_enabled.load(AtomicOrdering::Acquire)
    }

    /// Enable persist + serve-from-index + backfill. Creates empty files if needed.
    ///
    /// Does **not** gate Electrum: naive walk remains when off / hole.
    pub fn set_sptweaks_enabled(&self, on: bool, origin: Height) -> Result<(), QueryError> {
        self.sptweaks_origin
            .store(origin.0, AtomicOrdering::Release);
        if on {
            self.ensure_sp_tweaks(origin)?;
        }
        self.sptweaks_enabled.store(on, AtomicOrdering::Release);
        Ok(())
    }

    fn ensure_sp_tweaks(&self, origin: Height) -> Result<(), QueryError> {
        let mut g = self.sp_tweaks.lock().unwrap_or_else(|e| e.into_inner());
        if g.is_none() {
            *g = Some(SpTweaksTable::open_or_create(self.store.path(), origin)?);
            self.sptweaks_origin
                .store(origin.0, AtomicOrdering::Release);
        }
        Ok(())
    }

    pub fn sptweaks_origin(&self) -> Height {
        Height(self.sptweaks_origin.load(AtomicOrdering::Acquire))
    }

    pub fn sptweaks_next_height(&self) -> Option<Height> {
        let g = self.sp_tweaks.lock().unwrap_or_else(|e| e.into_inner());
        g.as_ref().map(|t| t.next_height())
    }

    /// Write one height of aligned per-tx tweaks (`None` = ineligible).
    ///
    /// No-op when the flag is off, the table is missing, `height` is not next,
    /// or `height` is not yet confirmed. `header_fk` must be the confirmed tip
    /// header at `height` (the idx does not store it).
    pub fn put_sp_tweaks_block(
        &self,
        height: Height,
        header_fk: Fk,
        records: &[Option<[u8; 33]>],
    ) -> Result<(), QueryError> {
        if !self.sptweaks_enabled() {
            return Ok(());
        }
        let g = self.sp_tweaks.lock().unwrap_or_else(|e| e.into_inner());
        let Some(t) = g.as_ref() else {
            return Ok(());
        };
        if height != t.next_height() {
            return Ok(());
        }
        match self.store.confirmed.get(height)? {
            None => return Ok(()),
            Some(fk) if fk != header_fk => {
                return Err(StoreError::Corrupt(
                    "sp_tweaks put header is not confirmed tip",
                ));
            }
            Some(_) => {}
        }
        t.put_block(height, records)
    }

    /// Consecutive heights: one body pwrite + one idx pwrite. Same checks as
    /// [`Self::put_sp_tweaks_block`] on each item; no-op if the first is not next.
    pub fn put_sp_tweaks_blocks(
        &self,
        items: &[(Height, Fk, Vec<Option<[u8; 33]>>)],
    ) -> Result<(), QueryError> {
        if items.is_empty() {
            return Ok(());
        }
        if !self.sptweaks_enabled() {
            return Ok(());
        }
        let g = self.sp_tweaks.lock().unwrap_or_else(|e| e.into_inner());
        let Some(t) = g.as_ref() else {
            return Ok(());
        };
        if items[0].0 != t.next_height() {
            return Ok(());
        }
        for (height, header_fk, _) in items {
            match self.store.confirmed.get(*height)? {
                None => return Ok(()),
                Some(fk) if fk != *header_fk => {
                    return Err(StoreError::Corrupt(
                        "sp_tweaks put header is not confirmed tip",
                    ));
                }
                Some(_) => {}
            }
        }
        let refs: Vec<(Height, &[Option<[u8; 33]>])> =
            items.iter().map(|(h, _, r)| (*h, r.as_slice())).collect();
        t.put_blocks(&refs).map_err(Into::into)
    }

    pub fn truncate_sp_tweaks_through_tip(&self, tip: Option<Height>) -> Result<(), QueryError> {
        let g = self.sp_tweaks.lock().unwrap_or_else(|e| e.into_inner());
        let Some(t) = g.as_ref() else {
            return Ok(());
        };
        t.truncate_through_tip(tip)
    }

    /// Indexed height, or `None` if hole / no table / missing header.
    ///
    /// Returns **only eligible** txs (`len=33`). See [`Self::load_thin_tweaks_range`].
    pub fn load_thin_tweaks(
        &self,
        height: Height,
    ) -> Result<Option<Vec<ThinTweakRow>>, QueryError> {
        let mut batch = self.load_thin_tweaks_range(
            height,
            ThinTweakRangeLimits {
                max_heights: 1,
                max_eligible: usize::MAX,
            },
        )?;
        Ok(batch.pop().map(|(_, rows)| rows))
    }

    /// Contiguous thin-index heights starting at `start`, stopped by tip hole,
    /// index hole, or [`ThinTweakRangeLimits`].
    ///
    /// Empty `Ok(vec![])` means the first height is not indexed (caller falls
    /// back per-height). Eligible Class A join is **one sequential `txout`
    /// span** from first..=last eligible fk in the wave (ineligible txout in
    /// the hole is included; `inwit` is not). `sp_tweaks` mutex is not held
    /// during Class A IO.
    pub fn load_thin_tweaks_range(
        &self,
        start: Height,
        limits: ThinTweakRangeLimits,
    ) -> Result<Vec<(Height, Vec<ThinTweakRow>)>, QueryError> {
        if limits.max_heights == 0 {
            return Ok(Vec::new());
        }
        // Plan under lock: copy eligible tweaks + create fks only.
        struct HeightPlan {
            height: Height,
            first_id: u64,
            /// (tx_index_in_block, tweak)
            elig: Vec<(u32, [u8; 33])>,
        }
        let plans: Vec<HeightPlan> = {
            let g = self.sp_tweaks.lock().unwrap_or_else(|e| e.into_inner());
            let Some(t) = g.as_ref() else {
                return Ok(Vec::new());
            };
            let mut meta: Vec<(Height, u64, u32)> = Vec::new();
            for step in 0..limits.max_heights {
                let h = Height(start.0.saturating_add(step));
                let Some(header_fk) = self.store.confirmed.get(h)? else {
                    break;
                };
                let Some((first_fk, n_tx)) = self.store.header_txs.get_range(header_fk)? else {
                    break;
                };
                let Some(first_id) = first_fk.get() else {
                    return Err(StoreError::InvalidFk);
                };
                meta.push((h, first_id, n_tx));
            }
            if meta.is_empty() {
                Vec::new()
            } else {
                let n_txs: Vec<u32> = meta.iter().map(|m| m.2).collect();
                match t.get_eligible_range(meta[0].0, &n_txs)? {
                    None => Vec::new(),
                    Some(eligs) => {
                        let mut plans = Vec::new();
                        let mut elig_total = 0usize;
                        for (i, elig) in eligs.into_iter().enumerate() {
                            let add = elig.len();
                            if !plans.is_empty()
                                && limits.max_eligible != usize::MAX
                                && elig_total.saturating_add(add) > limits.max_eligible
                            {
                                break;
                            }
                            elig_total = elig_total.saturating_add(add);
                            plans.push(HeightPlan {
                                height: meta[i].0,
                                first_id: meta[i].1,
                                elig,
                            });
                        }
                        plans
                    }
                }
            }
        };

        if plans.is_empty() {
            return Ok(Vec::new());
        }

        let mut elig_fks: Vec<Fk> = Vec::new();
        let mut tag: Vec<(usize, usize)> = Vec::new();
        for (pi, p) in plans.iter().enumerate() {
            for (ei, &(tx_i, _)) in p.elig.iter().enumerate() {
                elig_fks.push(Fk(p.first_id.saturating_add(u64::from(tx_i))));
                tag.push((pi, ei));
            }
        }

        let mut out_rows: Vec<Vec<ThinTweakRow>> = plans
            .iter()
            .map(|p| Vec::with_capacity(p.elig.len()))
            .collect();

        if !elig_fks.is_empty() {
            let (txids, ranges) = thin_join_txids_and_ranges(&self.store, &elig_fks)?;
            let mut span_off = u64::MAX;
            let mut span_end = 0u64;
            for r in &ranges {
                let (off, len) = require_thin_body_range(*r)?;
                span_off = span_off.min(off);
                span_end = span_end.max(off.saturating_add(len));
            }
            let span_len = span_end - span_off;
            self.store.txs.with_body_span(span_off, span_len, |raw| {
                for (i, r) in ranges.iter().enumerate() {
                    let (off, len) = r.unwrap();
                    let rel = (off - span_off) as usize;
                    let sl = raw.get(rel..rel.saturating_add(len as usize)).ok_or(
                        StoreError::Corrupt("invariant: thin tweak eligible body span truncated"),
                    )?;
                    let Some(txid) = txids.get(i).copied().flatten() else {
                        return Err(StoreError::Corrupt(
                            "invariant: thin tweak eligible txid missing",
                        ));
                    };
                    let (pi, ei) = tag[i];
                    let p2tr = self.store.txs.packed_p2tr_from_raw(sl)?;
                    out_rows[pi].push(ThinTweakRow {
                        txid,
                        tweak: plans[pi].elig[ei].1,
                        p2tr,
                    });
                }
                Ok(())
            })?;
            self.note_thin_tweak_body_bytes(span_len);
        }

        Ok(plans
            .into_iter()
            .zip(out_rows.into_iter())
            .map(|(p, rows)| (p.height, rows))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

    fn tmp_q() -> (std::path::PathBuf, Query) {
        let path = std::env::temp_dir().join(format!(
            "rbitcoin-q-sptweaks-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path).unwrap();
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let q = Query::open_or_create(&path).unwrap();
        (path, q)
    }

    #[test]
    fn put_and_load_noop_when_disabled() {
        let (dir, q) = tmp_q();
        assert!(!q.sptweaks_enabled());
        assert!(q.sptweaks_next_height().is_none());
        q.put_sp_tweaks_block(Height(0), Fk(1), &[None]).unwrap();
        q.truncate_sp_tweaks_through_tip(None).unwrap();
        assert!(q.load_thin_tweaks(Height(0)).unwrap().is_none());
        q.set_sptweaks_enabled(true, Height(0)).unwrap();
        assert!(q.sptweaks_enabled());
        assert_eq!(q.sptweaks_origin(), Height(0));
        assert_eq!(q.sptweaks_next_height(), Some(Height(0)));
        // No confirmed header → hole.
        assert!(q.load_thin_tweaks(Height(0)).unwrap().is_none());
        // Not next height is a no-op.
        q.put_sp_tweaks_block(Height(3), Fk(1), &[None]).unwrap();
        assert_eq!(q.sptweaks_next_height(), Some(Height(0)));
        q.set_sptweaks_enabled(true, Height(0)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_sp_tweaks_rejects_header_fk_mismatch() {
        let (dir, q) = tmp_q();
        q.set_sptweaks_enabled(true, Height(0)).unwrap();
        let h0 = header(0, Fk::NULL, None);
        let fk0 = q
            .connect_block(
                Height(0),
                &h0,
                &[TxApply {
                    tx: TxRecord {
                        txid: [1u8; 32],
                        version: 1,
                        locktime: 0,
                        input_start_fk: Fk::NULL,
                        input_count: 1,
                        output_start_fk: Fk::NULL,
                        output_count: 1,
                    },
                    inputs: vec![InputRecord::coinbase(u32::MAX, vec![0x00], vec![])],
                    outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
                }],
            )
            .unwrap();
        let err = q
            .put_sp_tweaks_block(Height(0), Fk(fk0.0.wrapping_add(1)), &[None])
            .unwrap_err();
        assert!(
            format!("{err}").contains("sp_tweaks put header is not confirmed tip"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wave_join_is_dense_packed_vs_sparse() {
        assert!(wave_join_is_dense(4, 10, 13));
        assert!(wave_join_is_dense(1, 10, 13));
        assert!(!wave_join_is_dense(1, 10, 14));
        assert!(!wave_join_is_dense(0, 10, 13));
        assert!(wave_join_is_dense(2, 100, 107));
        assert!(!wave_join_is_dense(2, 100, 108));
        assert!(!wave_join_is_dense(1, 20, 10));
    }

    #[test]
    fn thin_tweak_body_corrupt_strings_are_distinct() {
        let missing = require_thin_body_range(None).unwrap_err();
        let empty = require_thin_body_range(Some((8, 0))).unwrap_err();
        let ok = require_thin_body_range(Some((8, 16))).unwrap();
        assert_eq!(ok, (8, 16));
        let m = format!("{missing}");
        let e = format!("{empty}");
        assert!(m.contains("body missing"), "{m}");
        assert!(e.contains("body empty"), "{e}");
        assert_ne!(m, e);
    }

    #[test]
    fn put_blocks_advances_next_by_batch() {
        let (dir, q) = tmp_q();
        q.set_sptweaks_enabled(true, Height(0)).unwrap();
        let h0 = header(0, Fk::NULL, None);
        let cb = |tid: u8| TxApply {
            tx: TxRecord {
                txid: [tid; 32],
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord::coinbase(u32::MAX, vec![0x00], vec![])],
            outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
        };
        let fk0 = q.connect_block(Height(0), &h0, &[cb(1)]).unwrap();
        let h1 = header(1, fk0, Some(h0.hash));
        let fk1 = q.connect_block(Height(1), &h1, &[cb(2)]).unwrap();
        q.put_sp_tweaks_blocks(&[(Height(0), fk0, vec![None]), (Height(1), fk1, vec![None])])
            .unwrap();
        assert_eq!(q.sptweaks_next_height(), Some(Height(2)));
        assert!(q.load_thin_tweaks(Height(0)).unwrap().is_some());
        assert!(q.load_thin_tweaks(Height(1)).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn header(h: u32, prev_fk: Fk, prev_hash: Option<[u8; 32]>) -> HeaderRecord {
        let mut merkle = [0u8; 32];
        merkle[0..4].copy_from_slice(&h.to_le_bytes());
        merkle[5] = 0xec;
        let hash = match prev_hash {
            None => merkle,
            Some(ph) => rbitcoin_store::block_header_hash(1, &ph, &merkle, h + 1, 0x207f_ffff, h),
        };
        HeaderRecord {
            prev_fk,
            version: 1,
            timestamp: h + 1,
            bits: 0x207f_ffff,
            nonce: h,
            merkle_root: merkle,
            hash,
        }
    }

    fn p2wpkh_p2tr() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use bitcoin::hashes::hash160;
        use bitcoin::hashes::Hash;
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let ser = pk.serialize();
        let h160 = hash160::Hash::hash(&ser);
        let mut p2wpkh = vec![0x00, 0x14];
        p2wpkh.extend_from_slice(h160.as_ref());
        let (xonly, _) = pk.x_only_public_key();
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&xonly.serialize());
        (p2wpkh, p2tr, ser.to_vec())
    }

    /// Fat **inwit** between eligible txs must stay out of the `txout` span.
    #[test]
    fn load_thin_skips_fat_ineligible_between_eligible() {
        let (dir, q) = tmp_q();
        q.set_sptweaks_enabled(true, Height(0)).unwrap();
        let (p2wpkh, p2tr, ser) = p2wpkh_p2tr();
        let mut genesis_txid = [0u8; 32];
        genesis_txid[31] = 0xcb;
        let h0 = header(0, Fk::NULL, None);
        let fk0 = q
            .connect_block(
                Height(0),
                &h0,
                &[TxApply {
                    tx: TxRecord {
                        txid: genesis_txid,
                        version: 1,
                        locktime: 0,
                        input_start_fk: Fk::NULL,
                        input_count: 1,
                        output_start_fk: Fk::NULL,
                        output_count: 3,
                    },
                    inputs: vec![InputRecord::coinbase(u32::MAX, vec![0x00], vec![])],
                    outputs: vec![
                        OutputRecord::unspent(20_0000_0000, p2wpkh.clone()),
                        OutputRecord::unspent(20_0000_0000, p2wpkh.clone()),
                        OutputRecord::unspent(10_0000_0000, vec![0x51]),
                    ],
                }],
            )
            .unwrap();
        let err = q
            .put_sp_tweaks_block(Height(0), Fk(99), &[None])
            .unwrap_err();
        assert!(
            matches!(err, QueryError::Corrupt(m) if m.contains("not confirmed tip")),
            "{err:?}"
        );
        q.put_sp_tweaks_block(Height(0), fk0, &[None]).unwrap();
        let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];
        let mut tid_a = [0u8; 32];
        tid_a[0] = 0xaa;
        let mut tid_fat = [0u8; 32];
        tid_fat[0] = 0xfe;
        let mut tid_b = [0u8; 32];
        tid_b[0] = 0xbb;
        let spend =
            |prev: u32, txid: [u8; 32], outs: Vec<OutputRecord>, wit: Vec<Vec<u8>>| TxApply {
                tx: TxRecord {
                    txid,
                    version: 2,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 1,
                    output_start_fk: Fk::NULL,
                    output_count: outs.len() as u32,
                },
                inputs: vec![InputRecord {
                    prev_txid: genesis_txid,
                    create_fk,
                    prev_index: prev,
                    sequence: u32::MAX,
                    script_sig: vec![],
                    witness: wit,
                }],
                outputs: outs,
            };
        let h1 = header(1, fk0, Some(h0.hash));
        let header_fk = q
            .connect_block(
                Height(1),
                &h1,
                &[
                    spend(
                        0,
                        tid_a,
                        vec![OutputRecord::unspent(19_0000_0000, p2tr.clone())],
                        vec![vec![0u8; 64], ser.clone()],
                    ),
                    spend(
                        2,
                        tid_fat,
                        vec![OutputRecord::unspent(9_0000_0000, vec![0x51])],
                        vec![vec![0u8; 16_384]],
                    ),
                    spend(
                        1,
                        tid_b,
                        vec![OutputRecord::unspent(19_0000_0000, p2tr)],
                        vec![vec![0u8; 64], ser],
                    ),
                ],
            )
            .unwrap();
        let mut tw_a = [0x02; 33];
        tw_a[0] = 0x02;
        let mut tw_b = [0x03; 33];
        tw_b[0] = 0x03;
        q.put_sp_tweaks_block(Height(1), header_fk, &[Some(tw_a), None, Some(tw_b)])
            .unwrap();

        let fks = q.block_tx_fks(Height(1)).unwrap();
        let elig_a = q.store().tx_inwit_range(fks[0]).unwrap();
        let fat = q.store().tx_inwit_range(fks[1]).unwrap();
        let elig_b = q.store().tx_inwit_range(fks[2]).unwrap();
        assert!(
            fat.1 > 8_000,
            "fat ineligible inwit row too small: {}",
            fat.1
        );
        let elig_sum = elig_a.1.saturating_add(elig_b.1);
        assert!(
            fat.1 > elig_sum.saturating_mul(2),
            "need span/elig >> 2.5 (fat={} elig={})",
            fat.1,
            elig_sum
        );

        let _ = q.sample_reset_thin_tweak_body_bytes();
        let rows = q.load_thin_tweaks(Height(1)).unwrap().expect("indexed");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].txid, tid_a);
        assert_eq!(rows[1].txid, tid_b);
        assert_eq!(rows[0].tweak, tw_a);
        assert_eq!(rows[1].tweak, tw_b);
        assert_eq!(rows[0].p2tr.len(), 1);
        assert_eq!(rows[1].p2tr.len(), 1);
        let read = q.sample_reset_thin_tweak_body_bytes();
        assert!(
            read <= elig_sum.saturating_add(64),
            "thin serve must not read fat ineligible body (read={read} elig={elig_sum} fat={})",
            fat.1
        );
        assert!(
            read < fat.1,
            "read {read} must be smaller than the skipped fat row {}",
            fat.1
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Notify `output_pubkeys` come from `txout` only. One sequential span from
    /// first..=last eligible in the wave (ineligible txout in the hole is
    /// included; fat **inwit** stays out).
    #[test]
    fn load_thin_span_reads_ineligible_txout_between_eligible() {
        let (dir, q) = tmp_q();
        q.set_sptweaks_enabled(true, Height(0)).unwrap();
        let (p2wpkh, p2tr, ser) = p2wpkh_p2tr();
        let mut genesis_txid = [0u8; 32];
        genesis_txid[31] = 0xcb;
        let h0 = header(0, Fk::NULL, None);
        let fk0 = q
            .connect_block(
                Height(0),
                &h0,
                &[TxApply {
                    tx: TxRecord {
                        txid: genesis_txid,
                        version: 1,
                        locktime: 0,
                        input_start_fk: Fk::NULL,
                        input_count: 1,
                        output_start_fk: Fk::NULL,
                        output_count: 3,
                    },
                    inputs: vec![InputRecord::coinbase(u32::MAX, vec![0x00], vec![])],
                    outputs: vec![
                        OutputRecord::unspent(20_0000_0000, p2wpkh.clone()),
                        OutputRecord::unspent(20_0000_0000, p2wpkh.clone()),
                        OutputRecord::unspent(10_0000_0000, vec![0x51]),
                    ],
                }],
            )
            .unwrap();
        q.put_sp_tweaks_block(Height(0), fk0, &[None]).unwrap();
        let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];
        let mut tid_a = [0u8; 32];
        tid_a[0] = 0xaa;
        let mut tid_mid = [0u8; 32];
        tid_mid[0] = 0xfe;
        let mut tid_b = [0u8; 32];
        tid_b[0] = 0xbb;
        let fat_script = vec![0x51; 4096];
        let spend =
            |prev: u32, txid: [u8; 32], outs: Vec<OutputRecord>, wit: Vec<Vec<u8>>| TxApply {
                tx: TxRecord {
                    txid,
                    version: 2,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 1,
                    output_start_fk: Fk::NULL,
                    output_count: outs.len() as u32,
                },
                inputs: vec![InputRecord {
                    prev_txid: genesis_txid,
                    create_fk,
                    prev_index: prev,
                    sequence: u32::MAX,
                    script_sig: vec![],
                    witness: wit,
                }],
                outputs: outs,
            };
        let h1 = header(1, fk0, Some(h0.hash));
        let header_fk = q
            .connect_block(
                Height(1),
                &h1,
                &[
                    spend(
                        0,
                        tid_a,
                        vec![OutputRecord::unspent(19_0000_0000, p2tr.clone())],
                        vec![vec![0u8; 64], ser.clone()],
                    ),
                    spend(
                        2,
                        tid_mid,
                        vec![OutputRecord::unspent(9_0000_0000, fat_script)],
                        vec![vec![0u8; 64]],
                    ),
                    spend(
                        1,
                        tid_b,
                        vec![OutputRecord::unspent(19_0000_0000, p2tr)],
                        vec![vec![0u8; 64], ser],
                    ),
                ],
            )
            .unwrap();
        let mut tw_a = [0x02; 33];
        tw_a[0] = 0x02;
        let mut tw_b = [0x03; 33];
        tw_b[0] = 0x03;
        q.put_sp_tweaks_block(Height(1), header_fk, &[Some(tw_a), None, Some(tw_b)])
            .unwrap();

        let fks = q.block_tx_fks(Height(1)).unwrap();
        let mid_txout = q.store().txs.body_range(fks[1]).unwrap();
        assert!(
            mid_txout.1 >= 4096,
            "ineligible txout too small to observe span: {}",
            mid_txout.1
        );
        let elig_txout = q
            .store()
            .txs
            .body_range(fks[0])
            .unwrap()
            .1
            .saturating_add(q.store().txs.body_range(fks[2]).unwrap().1);

        let _ = q.sample_reset_thin_tweak_body_bytes();
        let rows = q.load_thin_tweaks(Height(1)).unwrap().expect("indexed");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].txid, tid_a);
        assert_eq!(rows[1].txid, tid_b);
        let read = q.sample_reset_thin_tweak_body_bytes();
        assert!(
            read >= mid_txout.1,
            "thin serve must read the txout span covering the ineligible hole \
             (read={read} mid_txout={} elig_txout={elig_txout})",
            mid_txout.1
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Multi-height range load must match sequential single-height loads.
    #[test]
    fn load_thin_range_matches_singles_and_stops_on_hole() {
        let (dir, q) = tmp_q();
        q.set_sptweaks_enabled(true, Height(0)).unwrap();
        let (p2wpkh, p2tr, ser) = p2wpkh_p2tr();
        let mut genesis_txid = [0u8; 32];
        genesis_txid[31] = 0xcb;
        let h0 = header(0, Fk::NULL, None);
        let fk0 = q
            .connect_block(
                Height(0),
                &h0,
                &[TxApply {
                    tx: TxRecord {
                        txid: genesis_txid,
                        version: 1,
                        locktime: 0,
                        input_start_fk: Fk::NULL,
                        input_count: 1,
                        output_start_fk: Fk::NULL,
                        output_count: 2,
                    },
                    inputs: vec![InputRecord::coinbase(u32::MAX, vec![0x00], vec![])],
                    outputs: vec![
                        OutputRecord::unspent(25_0000_0000, p2wpkh.clone()),
                        OutputRecord::unspent(25_0000_0000, p2wpkh),
                    ],
                }],
            )
            .unwrap();
        q.put_sp_tweaks_block(Height(0), fk0, &[None]).unwrap();
        let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];

        let spend = |prev: u32, tid: u8, tw: [u8; 33]| {
            let mut txid = [0u8; 32];
            txid[0] = tid;
            (
                TxApply {
                    tx: TxRecord {
                        txid,
                        version: 2,
                        locktime: 0,
                        input_start_fk: Fk::NULL,
                        input_count: 1,
                        output_start_fk: Fk::NULL,
                        output_count: 1,
                    },
                    inputs: vec![InputRecord {
                        prev_txid: genesis_txid,
                        create_fk,
                        prev_index: prev,
                        sequence: u32::MAX,
                        script_sig: vec![],
                        witness: vec![vec![0u8; 64], ser.clone()],
                    }],
                    outputs: vec![OutputRecord::unspent(24_0000_0000, p2tr.clone())],
                },
                tw,
                txid,
            )
        };
        let mut tw1 = [0x02; 33];
        tw1[0] = 0x02;
        let mut tw2 = [0x03; 33];
        tw2[0] = 0x03;
        let (tx1, tw1, tid1) = spend(0, 0xa1, tw1);
        let h1 = header(1, fk0, Some(h0.hash));
        let fk1 = q.connect_block(Height(1), &h1, &[tx1]).unwrap();
        q.put_sp_tweaks_block(Height(1), fk1, &[Some(tw1)]).unwrap();

        let (tx2, tw2, tid2) = spend(1, 0xa2, tw2);
        let h2 = header(2, fk1, Some(h1.hash));
        let fk2 = q.connect_block(Height(2), &h2, &[tx2]).unwrap();
        q.put_sp_tweaks_block(Height(2), fk2, &[Some(tw2)]).unwrap();

        // Contiguous 0..=2: height 0 empty eligible, 1 and 2 one each.
        let batch = q
            .load_thin_tweaks_range(Height(0), ThinTweakRangeLimits::default())
            .unwrap();
        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0].0, Height(0));
        assert!(batch[0].1.is_empty());
        assert_eq!(batch[1].1.len(), 1);
        assert_eq!(batch[1].1[0].txid, tid1);
        assert_eq!(batch[1].1[0].tweak, tw1);
        assert_eq!(batch[2].1[0].txid, tid2);
        assert_eq!(batch[2].1[0].tweak, tw2);

        for h in 0u32..=2 {
            let single = q.load_thin_tweaks(Height(h)).unwrap().expect("indexed");
            assert_eq!(single.len(), batch[h as usize].1.len());
            for (a, b) in single.iter().zip(batch[h as usize].1.iter()) {
                assert_eq!(a.txid, b.txid);
                assert_eq!(a.tweak, b.tweak);
                assert_eq!(a.p2tr, b.p2tr);
            }
        }

        let fks1 = q.block_tx_fks(Height(1)).unwrap();
        let fks2 = q.block_tx_fks(Height(2)).unwrap();
        let first = fks1[0].get().unwrap();
        let last = fks2[0].get().unwrap();
        assert!(
            wave_join_is_dense(2, first, last),
            "fully eligible consecutive txs must take the dense join"
        );

        // max_heights=1
        let one = q
            .load_thin_tweaks_range(
                Height(1),
                ThinTweakRangeLimits {
                    max_heights: 1,
                    max_eligible: 8192,
                },
            )
            .unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].0, Height(1));

        // max_eligible=1 stops after first height that contributes elig (h1).
        let budg = q
            .load_thin_tweaks_range(
                Height(1),
                ThinTweakRangeLimits {
                    max_heights: 10,
                    max_eligible: 1,
                },
            )
            .unwrap();
        assert_eq!(budg.len(), 1);
        assert_eq!(budg[0].0, Height(1));

        // Hole: no height 3 index → start at 3 is empty; start at 2 is only h2.
        assert!(q
            .load_thin_tweaks_range(Height(3), ThinTweakRangeLimits::default())
            .unwrap()
            .is_empty());
        let only2 = q
            .load_thin_tweaks_range(Height(2), ThinTweakRangeLimits::default())
            .unwrap();
        assert_eq!(only2.len(), 1);
        assert_eq!(only2[0].0, Height(2));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
