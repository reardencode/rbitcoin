//! Tip-window revalidation on store open (Bitcoin Core `checkblocks`-style).
//!
//! Default window is [`VERIFY_TIP_BLOCKS`] (6) for both structural checks and
//! Class A merkle content. Runs **before** the one complement Class C repair
//! so the fence matches the post-revalidate tip.
//!
//! Soft sidecar [`TIP_SEAL_NAME`]: written after a successful connect/disconnect
//! Class C barrier so a kill that advanced `confirmed` without a complete seal
//! can be clamped before revalidation.

use crate::error::StoreError;
use crate::header_table::block_header_hash;
use crate::store::Store;
use bitcoin_hashes::{sha256, Hash, HashEngine};
use rbitcoin_primitives::{schema_file_openable, Height, SCHEMA_VERSION, STORE_MAGIC};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;

/// Core `-checkblocks` default: re-read the last N confirmed blocks at open.
pub const VERIFY_TIP_BLOCKS: u32 = 6;

/// Soft tip seal file under `store/` (not a SCHEMA_VERSION bump).
pub const TIP_SEAL_NAME: &str = "tip_seal";

/// On-disk tip seal after a complete Class C barrier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TipSeal {
    pub tip_height: u32,
    pub tip_hash: [u8; 32],
    /// `confirmed` length (= tip_height + 1 when non-empty).
    pub confirmed_len: u64,
    pub generation: u64,
}

impl TipSeal {
    const BYTES: usize = 60;

    pub fn path(dir: &Path) -> std::path::PathBuf {
        dir.join(TIP_SEAL_NAME)
    }

    pub fn load(dir: &Path) -> Result<Option<Self>, StoreError> {
        let p = Self::path(dir);
        if !p.exists() {
            return Ok(None);
        }
        let mut f = OpenOptions::new()
            .read(true)
            .open(&p)
            .map_err(|e| StoreError::io(&p, e))?;
        let mut buf = [0u8; Self::BYTES];
        f.read_exact(&mut buf).map_err(|e| StoreError::io(&p, e))?;
        if buf[0..4] != STORE_MAGIC {
            return Err(StoreError::BadMagic);
        }
        let ver = u16::from_le_bytes(buf[4..6].try_into().unwrap());
        if !schema_file_openable(ver) {
            return Err(StoreError::BadSchema(ver));
        }
        Ok(Some(Self {
            tip_height: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            confirmed_len: u64::from_le_bytes(buf[12..20].try_into().unwrap()),
            generation: u64::from_le_bytes(buf[20..28].try_into().unwrap()),
            tip_hash: buf[28..60].try_into().unwrap(),
        }))
    }

    pub fn store(&self, dir: &Path) -> Result<(), StoreError> {
        let p = Self::path(dir);
        let mut buf = [0u8; Self::BYTES];
        buf[0..4].copy_from_slice(&STORE_MAGIC);
        buf[4..6].copy_from_slice(&SCHEMA_VERSION.to_le_bytes());
        // 6..8 reserved
        buf[8..12].copy_from_slice(&self.tip_height.to_le_bytes());
        buf[12..20].copy_from_slice(&self.confirmed_len.to_le_bytes());
        buf[20..28].copy_from_slice(&self.generation.to_le_bytes());
        buf[28..60].copy_from_slice(&self.tip_hash);
        let tmp = p.with_extension("tip_seal.tmp");
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)
                .map_err(|e| StoreError::io(&tmp, e))?;
            f.write_all(&buf).map_err(|e| StoreError::io(&tmp, e))?;
            f.sync_all().map_err(|e| StoreError::io(&tmp, e))?;
        }
        std::fs::rename(&tmp, &p).map_err(|e| StoreError::io(&p, e))?;
        Ok(())
    }
}

/// Result of [`Store::revalidate_tip_window`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TipRevalidateReport {
    /// Confirmed tip height before any shrink (`None` if empty chain).
    pub tip_before: Option<u32>,
    /// Tip after shrink (`None` if emptied).
    pub tip_after: Option<u32>,
    /// First height that failed (if any).
    pub first_bad_height: Option<u32>,
    /// Human-readable reason for first_bad (for logs/tests).
    pub first_bad_reason: Option<&'static str>,
    /// Header_fk body associations cleared (out-of-bounds or merkle fail).
    pub bodies_cleared: u64,
    /// True when confirmed tip was truncated.
    pub tip_shrunk: bool,
}

impl TipRevalidateReport {
    pub fn is_clean(&self) -> bool {
        self.first_bad_height.is_none() && !self.tip_shrunk && self.bodies_cleared == 0
    }
}

/// Bitcoin block merkle root from leaf txids (internal byte order).
pub fn merkle_root_from_txids(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            if let Some(last) = level.last().copied() {
                level.push(last);
            }
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(hash256_concat(&pair[0], &pair[1]));
        }
        level = next;
    }
    level[0]
}

fn hash256_concat(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut eng = sha256::HashEngine::default();
    eng.input(a);
    eng.input(b);
    let mid = sha256::Hash::from_engine(eng);
    let mut eng2 = sha256::HashEngine::default();
    eng2.input(mid.as_byte_array());
    sha256::Hash::from_engine(eng2).to_byte_array()
}

impl Store {
    /// Persist tip seal after a complete Class C tip barrier (connect or disconnect).
    ///
    /// Soft: if tip header is not loadable (synthetic Class C barrier tests, or
    /// mid-repair), skip the seal rather than failing the barrier — open
    /// revalidate still walks the tip window.
    pub fn publish_tip_seal(&self) -> Result<(), StoreError> {
        let Some(tip) = self.confirmed.tip_height() else {
            let p = TipSeal::path(self.path());
            let _ = std::fs::remove_file(&p);
            return Ok(());
        };
        let Some(fk) = self.confirmed.get(tip)? else {
            return Ok(());
        };
        let Ok(rec) = self.headers.get(fk) else {
            return Ok(());
        };
        let prev_gen = TipSeal::load(self.path())?
            .map(|s| s.generation)
            .unwrap_or(0);
        let seal = TipSeal {
            tip_height: tip.0,
            tip_hash: rec.hash,
            confirmed_len: u64::from(tip.0) + 1,
            generation: prev_gen.saturating_add(1),
        };
        seal.store(self.path())
    }

    /// Revalidate the last [`VERIFY_TIP_BLOCKS`] confirmed heights (structure + merkle).
    ///
    /// On failure: clear bad Class A associations and/or shrink tip to the last
    /// good height, flush confirmed, then `repair_class_c_above_tip`.
    pub fn revalidate_tip_window(&self) -> Result<TipRevalidateReport, StoreError> {
        self.revalidate_tip_window_n(VERIFY_TIP_BLOCKS)
    }

    /// Same as [`Self::revalidate_tip_window`] with an explicit window (tests).
    pub fn revalidate_tip_window_n(&self, n: u32) -> Result<TipRevalidateReport, StoreError> {
        let mut report = TipRevalidateReport::default();
        if let Some(h) = self.confirmed.tip_height() {
            report.tip_before = Some(h.0);
        }

        // HWM can include a trailing run of null slots (crash mid-grow). Trim
        // the whole suffix in one shot so the 6-height window sees a real tip.
        let trimmed = self.confirmed.trim_trailing_nulls()?;
        if trimmed > 0 {
            self.flush_confirmed_only()?;
            self.rebuild_height_fence()?;
            let _ = self.repair_class_c_above_tip()?;
            report.tip_shrunk = true;
            eprintln!("rbitcoin: trimmed {trimmed} trailing null confirmed[] slots");
        }

        // Soft seal: clamp confirmed tip that advanced without a complete seal write.
        if let Some(seal) = TipSeal::load(self.path())? {
            if let Some(tip) = self.confirmed.tip_height() {
                if tip.0 > seal.tip_height {
                    // Unsealed extension past last barrier seal — drop to sealed tip.
                    self.shrink_tip_to(Some(seal.tip_height), &mut report)?;
                } else if tip.0 == seal.tip_height {
                    if let Some(fk) = self.confirmed.get(tip)? {
                        if let Ok(rec) = self.headers.get(fk) {
                            if rec.hash != seal.tip_hash {
                                // Tip hash disagrees with seal — drop tip block.
                                let lg = tip.0.checked_sub(1);
                                self.shrink_tip_to(lg, &mut report)?;
                            }
                        }
                    }
                }
            }
        }

        let Some(tip) = self.confirmed.tip_height() else {
            report.tip_before = report.tip_before.or(None);
            report.tip_after = None;
            return Ok(report);
        };
        if report.tip_before.is_none() {
            report.tip_before = Some(tip.0);
        }
        if n == 0 {
            report.tip_after = Some(tip.0);
            return Ok(report);
        }

        let lo = tip.0.saturating_sub(n.saturating_sub(1));
        let tx_count = self.txs.count();
        let mut last_good: Option<u32> = if lo == 0 { None } else { Some(lo - 1) };
        // Heights below the window are assumed good for shrink baseline when lo > 0.

        for h in lo..=tip.0 {
            match self.check_confirmed_height(Height(h), tx_count, &mut report) {
                Ok(()) => last_good = Some(h),
                Err(reason) => {
                    report.first_bad_height = Some(h);
                    report.first_bad_reason = Some(reason);
                    break;
                }
            }
        }

        if report.first_bad_height.is_some() {
            self.shrink_tip_to(last_good, &mut report)?;
        } else {
            report.tip_after = Some(tip.0);
        }

        if report.bodies_cleared > 0 {
            self.header_txs.flush()?;
        }
        let _ = self.publish_tip_seal();
        Ok(report)
    }

    /// Structural + content check for one confirmed height.
    ///
    /// Returns `Err(reason)` on first hard failure that requires tip shrink.
    /// Body clear alone (without tip claim failure) is counted in report and Ok.
    fn check_confirmed_height(
        &self,
        height: Height,
        tx_count: u64,
        report: &mut TipRevalidateReport,
    ) -> Result<(), &'static str> {
        let Some(fk) = self.confirmed.get(height).map_err(|_| "confirmed read")? else {
            return Err("confirmed null header_fk");
        };
        let rec = match self.headers.get(fk) {
            Ok(r) => r,
            Err(_) => return Err("header load"),
        };

        if height.0 == 0 {
            if !rec.prev_fk.is_null() {
                return Err("genesis prev_fk non-null");
            }
            let zeros = [0u8; 32];
            let expect = block_header_hash(
                rec.version,
                &zeros,
                &rec.merkle_root,
                rec.timestamp,
                rec.bits,
                rec.nonce,
            );
            if expect != rec.hash {
                return Err("genesis header hash mismatch");
            }
        } else {
            let parent_h = Height(height.0 - 1);
            let Some(parent_fk) = self
                .confirmed
                .get(parent_h)
                .map_err(|_| "parent confirmed read")?
            else {
                return Err("parent confirmed null");
            };
            if rec.prev_fk != parent_fk {
                return Err("prev_fk != confirmed parent");
            }
            let parent = match self.headers.get(parent_fk) {
                Ok(p) => p,
                Err(_) => return Err("parent header load"),
            };
            let expect = block_header_hash(
                rec.version,
                &parent.hash,
                &rec.merkle_root,
                rec.timestamp,
                rec.bits,
                rec.nonce,
            );
            if expect != rec.hash {
                return Err("header hash mismatch vs parent");
            }
        }

        match self.header_txs.get_range(fk) {
            Ok(None) => Ok(()), // no body — ok for structural tip (unarchived tip rare)
            Ok(Some((first, count))) => {
                if count == 0 || first.is_null() {
                    let _ = self.header_txs.clear_body(fk);
                    report.bodies_cleared = report.bodies_cleared.saturating_add(1);
                    return Err("header_txs empty association");
                }
                let last = first.0.saturating_add(u64::from(count)).saturating_sub(1);
                if first.0 == 0 || last > tx_count {
                    let _ = self.header_txs.clear_body(fk);
                    report.bodies_cleared = report.bodies_cleared.saturating_add(1);
                    return Err("header_txs range OOB");
                }
                let leaves = match self.txs.body_txid_range(first.0, last) {
                    Ok(v) if v.len() == count as usize => v,
                    Ok(_) => {
                        let _ = self.header_txs.clear_body(fk);
                        report.bodies_cleared = report.bodies_cleared.saturating_add(1);
                        return Err("txid.body short for header_txs range");
                    }
                    Err(_) => {
                        let _ = self.header_txs.clear_body(fk);
                        report.bodies_cleared = report.bodies_cleared.saturating_add(1);
                        return Err("txid.body read");
                    }
                };
                let root = merkle_root_from_txids(&leaves);
                if root != rec.merkle_root {
                    let _ = self.header_txs.clear_body(fk);
                    report.bodies_cleared = report.bodies_cleared.saturating_add(1);
                    return Err("merkle root mismatch");
                }
                match self.strong_tx.all_strong_range(first, count) {
                    Ok(true) => Ok(()),
                    Ok(false) => Err("strong bits missing in tip window"),
                    Err(_) => Err("strong_tx read"),
                }
            }
            Err(_) => Err("header_txs read"),
        }
    }

    /// Truncate confirmed tip to `last_good` (inclusive), or empty if `None`.
    fn shrink_tip_to(
        &self,
        last_good: Option<u32>,
        report: &mut TipRevalidateReport,
    ) -> Result<(), StoreError> {
        let Some(tip) = self.confirmed.tip_height() else {
            report.tip_after = None;
            return Ok(());
        };
        let target_tip = last_good;
        match target_tip {
            Some(lg) if lg >= tip.0 => {
                report.tip_after = Some(tip.0);
                return Ok(());
            }
            _ => {}
        }

        let mut cur = tip.0;
        loop {
            let keep = match target_tip {
                Some(lg) => cur > lg,
                None => true,
            };
            if !keep {
                break;
            }
            self.confirmed.disconnect_tip(Height(cur))?;
            if cur == 0 {
                break;
            }
            cur -= 1;
            if target_tip == Some(cur) {
                break;
            }
            if self.confirmed.tip_height().is_none() {
                break;
            }
        }

        self.flush_confirmed_only()?;
        self.rebuild_height_fence()?;
        let _ = self.repair_class_c_above_tip()?;
        report.tip_shrunk = true;
        report.tip_after = self.confirmed.tip_height().map(|h| h.0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header_table::HeaderRecord;
    use crate::tx_table::{InputRecord, OutputRecord, TxRecord};
    use rbitcoin_primitives::Fk;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp() -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("rbitcoin-integrity-{n}"));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn hdr(prev: Fk, parent_hash: [u8; 32], salt: u8) -> HeaderRecord {
        let mut merkle = [0u8; 32];
        merkle[0] = salt;
        hdr_merkle(prev, parent_hash, salt, merkle)
    }

    fn hdr_merkle(prev: Fk, parent_hash: [u8; 32], salt: u8, merkle: [u8; 32]) -> HeaderRecord {
        let version = 1i32;
        let timestamp = u32::from(salt) + 1;
        let bits = 0x207fffff;
        let nonce = u32::from(salt);
        let hash = if prev.is_null() {
            block_header_hash(version, &[0u8; 32], &merkle, timestamp, bits, nonce)
        } else {
            block_header_hash(version, &parent_hash, &merkle, timestamp, bits, nonce)
        };
        HeaderRecord {
            prev_fk: prev,
            version,
            timestamp,
            bits,
            nonce,
            merkle_root: merkle,
            hash,
        }
    }

    fn put_coinbase(s: &Store, salt: u8) -> Fk {
        let rec = TxRecord {
            txid: [salt; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        };
        let ins = vec![InputRecord::coinbase(u32::MAX, vec![salt], vec![])];
        let outs = vec![OutputRecord::unspent(50, vec![0x51])];
        s.put_tx_full_batch_indexed(&[(rec, ins, outs)], true)
            .unwrap()[0]
    }

    #[test]
    fn merkle_root_single_and_pair() {
        let a = [1u8; 32];
        assert_eq!(merkle_root_from_txids(&[a]), a);
        let b = [2u8; 32];
        let root = merkle_root_from_txids(&[a, b]);
        assert_eq!(root, hash256_concat(&a, &b));
    }

    #[test]
    fn clean_header_chain_revalidate_no_shrink() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        let mut parent_hash = [0u8; 32];
        let mut prev = Fk::NULL;
        for h in 0u32..4 {
            let rec = hdr(prev, parent_hash, h as u8);
            parent_hash = rec.hash;
            let fk = s.put_header(&rec).unwrap();
            prev = fk;
            s.confirmed.set(Height(h), fk).unwrap();
        }
        s.flush_class_c_tip().unwrap();
        s.headers.flush().unwrap();

        let r = s.revalidate_tip_window_n(6).unwrap();
        assert!(r.is_clean(), "clean chain should not shrink: {r:?}");
        assert_eq!(s.confirmed.tip_height(), Some(Height(3)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn poison_prev_edge_shrinks_tip() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        let g = hdr(Fk::NULL, [0u8; 32], 0);
        let g_fk = s.put_header(&g).unwrap();
        s.confirmed.set(Height(0), g_fk).unwrap();
        let a = hdr(g_fk, g.hash, 1);
        let a_fk = s.put_header(&a).unwrap();
        s.confirmed.set(Height(1), a_fk).unwrap();
        let b = hdr(a_fk, a.hash, 2);
        let b_fk = s.put_header(&b).unwrap();
        s.confirmed.set(Height(2), b_fk).unwrap();
        // Steal tip height 2 to point at G (false conf edge).
        s.confirmed.set(Height(2), g_fk).unwrap();
        s.flush_class_c_tip().unwrap();

        let r = s.revalidate_tip_window_n(6).unwrap();
        assert!(r.tip_shrunk, "must shrink: {r:?}");
        assert_eq!(r.first_bad_reason, Some("prev_fk != confirmed parent"));
        assert_eq!(s.confirmed.tip_height(), Some(Height(1)));
        assert_eq!(r.tip_after, Some(1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tip_seal_clamps_unsealed_extension() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        let g = hdr(Fk::NULL, [0u8; 32], 0);
        let g_fk = s.put_header(&g).unwrap();
        s.confirmed.set(Height(0), g_fk).unwrap();
        s.flush_class_c_tip().unwrap();
        let seal = TipSeal::load(s.path())
            .unwrap()
            .expect("seal after tip barrier");
        assert_eq!(seal.tip_height, 0);
        assert_eq!(seal.tip_hash, g.hash);

        // Extend tip in RAM + flush confirmed only *without* updating seal:
        // simulate by writing a higher tip then restoring old seal file.
        let a = hdr(g_fk, g.hash, 1);
        let a_fk = s.put_header(&a).unwrap();
        s.confirmed.set(Height(1), a_fk).unwrap();
        s.confirmed.flush().unwrap();
        // Overwrite seal with the old tip-0 seal (as if barrier never finished).
        seal.store(s.path()).unwrap();
        assert_eq!(s.confirmed.tip_height(), Some(Height(1)));

        let r = s.revalidate_tip_window_n(6).unwrap();
        assert!(r.tip_shrunk, "seal clamp must shrink: {r:?}");
        assert_eq!(s.confirmed.tip_height(), Some(Height(0)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merkle_mismatch_clears_body_and_shrinks() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        let g = hdr(Fk::NULL, [0u8; 32], 0);
        let g_fk = s.put_header(&g).unwrap();
        s.confirmed.set(Height(0), g_fk).unwrap();
        let tx_fk = put_coinbase(&s, 9);
        let txid = s.txs.body_txid(tx_fk).unwrap();
        // Header merkle is salt-based, not txid → S3 fail.
        s.header_txs.put_range(g_fk, tx_fk, 1).unwrap();
        // Ensure genesis hash still consistent with its merkle field (no rewrite).
        let _ = txid;
        s.flush_class_c_tip().unwrap();
        s.header_txs.flush().unwrap();
        s.txs.flush().unwrap();

        let r = s.revalidate_tip_window_n(6).unwrap();
        assert_eq!(r.first_bad_reason, Some("merkle root mismatch"));
        assert!(r.bodies_cleared >= 1);
        assert!(r.tip_shrunk);
        assert!(s.confirmed.tip_height().is_none());
        assert!(!s.header_txs.has_body(g_fk).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tip_window_missing_strong_shrinks() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        let mut parent_hash = [0u8; 32];
        let mut prev = Fk::NULL;
        let mut tip_tx = Fk::NULL;
        for h in 0u32..3 {
            let tx_fk = put_coinbase(&s, h as u8 + 1);
            let txid = s.txs.body_txid(tx_fk).unwrap();
            let rec = hdr_merkle(prev, parent_hash, h as u8, txid);
            parent_hash = rec.hash;
            let hfk = s.put_header(&rec).unwrap();
            s.header_txs.put_range(hfk, tx_fk, 1).unwrap();
            s.strong_tx.set_strong(tx_fk, hfk).unwrap();
            s.confirmed.set(Height(h), hfk).unwrap();
            prev = hfk;
            tip_tx = tx_fk;
        }
        s.rebuild_height_fence().unwrap();
        s.flush_class_c_tip().unwrap();
        s.headers.flush().unwrap();
        s.txs.flush().unwrap();
        s.header_txs.flush().unwrap();
        assert_eq!(s.confirmed.tip_height(), Some(Height(2)));
        s.strong_tx.set_unstrong(tip_tx).unwrap();

        let r = s.revalidate_tip_window_n(6).unwrap();
        assert_eq!(
            r.first_bad_reason,
            Some("strong bits missing in tip window")
        );
        assert!(r.tip_shrunk, "must shrink: {r:?}");
        assert_eq!(s.confirmed.tip_height(), Some(Height(1)));
        assert_eq!(
            s.tx_height_get(tip_tx).unwrap(),
            None,
            "fence must drop the disconnected height"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 20 trailing null `confirmed[]` slots must become the last real tip in
    /// one revalidate (the 6-height window alone only walks the tail).
    #[test]
    fn trailing_null_confirmed_slots_trimmed_in_one_open() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        let mut parent_hash = [0u8; 32];
        let mut prev = Fk::NULL;
        for h in 0u32..4 {
            let rec = hdr(prev, parent_hash, h as u8);
            parent_hash = rec.hash;
            let fk = s.put_header(&rec).unwrap();
            prev = fk;
            s.confirmed.set(Height(h), fk).unwrap();
        }
        s.headers.flush().unwrap();
        s.confirmed.flush().unwrap();
        // No tip seal — seal clamp must not mask the suffix-null case.
        drop(s);

        let path = dir.join("confirmed.body");
        let f =
            crate::file::TableFile::open(&path, rbitcoin_primitives::TableKind::Confirmed).unwrap();
        let n = (f.logical_len() - crate::file::FILE_HEADER_LEN as u64) / 8;
        assert_eq!(n, 4, "four real confirmed heights");
        let extra = 20u64;
        let zeros = vec![0u8; (extra * 8) as usize];
        f.write_at(crate::file::FILE_HEADER_LEN as u64 + n * 8, &zeros)
            .unwrap();
        f.flush().unwrap();
        drop(f);

        let s = Store::open_tiny(&dir).unwrap();
        assert_eq!(
            s.confirmed.tip_height(),
            Some(Height(23)),
            "HWM includes 20 trailing nulls"
        );
        let r = s.revalidate_tip_window_n(6).unwrap();
        assert_eq!(
            s.confirmed.tip_height(),
            Some(Height(3)),
            "one open must drop the whole null suffix; report={r:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
