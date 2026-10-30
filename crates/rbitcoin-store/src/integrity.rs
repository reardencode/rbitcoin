//! Tip-window revalidation on store open (Bitcoin Core `checkblocks`-style).
//!
//! Default window is [`VERIFY_TIP_BLOCKS`] (6) for both structural checks and
//! Class A merkle content. Runs **before** the one complement Class C repair
//! so the fence matches the post-revalidate tip.
//!
//! Soft sidecar [`TIP_SEAL_NAME`]: written after a successful connect/disconnect
//! Class C barrier so a kill that advanced `confirmed` without a complete seal
//! can be clamped before revalidation. A sealed tip whose tx range ends past
//! the durable create count is corrupt: the barrier does not write that tip.

use crate::error::StoreError;
use crate::header_table::block_header_hash;
use crate::store::Store;
use rbitcoin_primitives::{
    merkle_root_from_txids, schema_file_openable, Fk, Height, SCHEMA_VERSION, STORE_MAGIC,
};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;

/// Core `-checkblocks` default: re-read the last N confirmed blocks at open.
pub const VERIFY_TIP_BLOCKS: u32 = 6;

/// Progress cadence while the open window walks confirmed heights.
#[doc(hidden)]
pub const TIP_REVALIDATE_STATUS_MS: u128 = 10_000;

/// Start, 10s progress, and done lines for one tip-window walk.
#[doc(hidden)]
pub struct TipRevalidateLog {
    pub started: std::time::Instant,
    pub logged_at: std::time::Instant,
    pub count: u64,
    pub walked: u64,
}

impl TipRevalidateLog {
    #[doc(hidden)]
    pub fn start(lo: u32, tip: u32) -> Self {
        let count = u64::from(tip - lo) + 1;
        rbitcoin_log::info!("store: tip revalidate {lo}..={tip} ({count} heights)");
        let started = std::time::Instant::now();
        Self {
            started,
            logged_at: started,
            count,
            walked: 0,
        }
    }

    #[doc(hidden)]
    pub fn step(&mut self, height: u32) {
        self.walked += 1;
        if self.logged_at.elapsed().as_millis() >= TIP_REVALIDATE_STATUS_MS {
            rbitcoin_log::info!(
                "store: tip revalidate {}/{} height={height}",
                self.walked,
                self.count
            );
            self.logged_at = std::time::Instant::now();
        }
    }

    #[doc(hidden)]
    pub fn done(&self, report: &TipRevalidateReport) {
        let height = match report.tip_after {
            Some(h) => h.to_string(),
            None => "none".to_string(),
        };
        let ms = self.started.elapsed().as_millis();
        if let Some(bad) = report.first_bad_height {
            rbitcoin_log::info!(
                "store: tip revalidate done height={height} ms={ms} bad={bad} reason={}",
                report.first_bad_reason.unwrap_or("")
            );
        } else {
            rbitcoin_log::info!("store: tip revalidate done height={height} ms={ms}");
        }
    }
}

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
    #[doc(hidden)]
    pub const BYTES: usize = 60;

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
        if let Some(parent) = p.parent() {
            crate::file::fsync_parent_dir(parent).map_err(|e| StoreError::io(parent, e))?;
        }
        Ok(())
    }
}

/// Result of [`Store::revalidate_tip_window_n`].
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

    #[doc(hidden)]
    pub fn effective_checkblocks(&self, n: u32) -> Result<u32, StoreError> {
        // A missing marker is not "durable through nothing". Heights below the
        // last six can still be torn, and `n == 0` is the only whole-chain walk.
        let Some(durable) =
            crate::spend_durable::SpendDurable::load(self.path())?.map(|m| m.durable_through())
        else {
            return Ok(0);
        };
        Ok(crate::spend_durable::widen_checkblocks(
            n,
            self.confirmed.tip_height().map(|h| h.0),
            Some(durable),
        ))
    }

    /// Revalidate confirmed heights (structure + merkle).
    ///
    /// `n == 0` walks from genesis (Core `-checkblocks=0`). A missing
    /// `spend_durable` marker is that same walk: nothing has been device-flushed.
    /// A present marker widens any other window to at least [`VERIFY_TIP_BLOCKS`]
    /// and far enough to cover heights above that marker.
    pub fn revalidate_tip_window_n(&self, n: u32) -> Result<TipRevalidateReport, StoreError> {
        let n = self.effective_checkblocks(n)?;
        let mut report = TipRevalidateReport::default();
        if let Some(h) = self.confirmed.tip_height() {
            report.tip_before = Some(h.0);
        }
        let write = crate::array_table::ClassCWrite::new();

        // HWM can include a trailing run of null slots (crash mid-grow). Trim
        // the whole suffix in one shot so the 6-height window sees a real tip.
        let trimmed = self.confirmed.trim_trailing_nulls(&write)?;
        if trimmed > 0 {
            self.flush_confirmed_only()?;
            self.rebuild_height_fence()?;
            self.persist_class_c_repair()?;
            report.tip_shrunk = true;
            eprintln!("rbitcoin: trimmed {trimmed} trailing null confirmed[] slots");
        }

        // Soft seal: clamp confirmed tip that advanced without a complete seal write.
        if let Some(seal) = TipSeal::load(self.path())? {
            if let Some(tip) = self.confirmed.tip_height() {
                if tip.0 > seal.tip_height {
                    // Unsealed extension past last barrier seal — drop to sealed tip.
                    self.shrink_tip_to(&write, Some(seal.tip_height), &mut report)?;
                } else if tip.0 == seal.tip_height {
                    if let Some(fk) = self.confirmed.get(tip)? {
                        if let Ok(rec) = self.headers.get(fk) {
                            if rec.hash != seal.tip_hash {
                                let lg = tip.0.checked_sub(1);
                                self.shrink_tip_to(&write, lg, &mut report)?;
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
        // Core `-checkblocks=0` (and negatives mapped to 0 by the node) = all.
        let lo = if n == 0 {
            0
        } else {
            tip.0.saturating_sub(n.saturating_sub(1))
        };
        let tx_count = self.txs.count();
        let mut last_good: Option<u32> = if lo == 0 { None } else { Some(lo - 1) };
        // Heights below the window are assumed good for shrink baseline when lo > 0.
        let mut progress = TipRevalidateLog::start(lo, tip.0);

        for h in lo..=tip.0 {
            match self.check_confirmed_height(&write, Height(h), tx_count, &mut report) {
                Ok(()) => last_good = Some(h),
                Err(reason) => {
                    report.first_bad_height = Some(h);
                    report.first_bad_reason = Some(reason);
                    break;
                }
            }
            progress.step(h);
        }

        if report.first_bad_height.is_some() {
            self.shrink_tip_to(&write, last_good, &mut report)?;
        } else {
            report.tip_after = Some(tip.0);
        }

        if report.bodies_cleared > 0 {
            self.header_txs.flush()?;
        }
        let _ = self.publish_tip_seal();
        progress.done(&report);
        Ok(report)
    }

    /// Structural + content check for one confirmed height.
    ///
    /// Returns `Err(reason)` on first hard failure that requires tip shrink.
    /// Body clear alone (without tip claim failure) is counted in report and Ok.
    #[doc(hidden)]
    pub fn check_confirmed_height(
        &self,
        write: &crate::array_table::ClassCWrite,
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
            Ok(None) => Ok(()),
            Ok(Some((first, count))) => self.check_header_tx_range(
                write,
                fk,
                first,
                count,
                tx_count,
                &rec.merkle_root,
                report,
            ),
            Err(_) => Err("header_txs read"),
        }
    }

    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn check_header_tx_range(
        &self,
        write: &crate::array_table::ClassCWrite,
        fk: Fk,
        first: Fk,
        count: u32,
        tx_count: u64,
        merkle_root: &[u8; 32],
        report: &mut TipRevalidateReport,
    ) -> Result<(), &'static str> {
        if count == 0 || first.is_null() {
            let _ = self.header_txs.clear_body(write, fk);
            report.bodies_cleared = report.bodies_cleared.saturating_add(1);
            return Err("header_txs empty association");
        }
        let last = first.0.saturating_add(u64::from(count)).saturating_sub(1);
        if first.0 == 0 || last > tx_count {
            let _ = self.header_txs.clear_body(write, fk);
            report.bodies_cleared = report.bodies_cleared.saturating_add(1);
            return Err("header_txs range OOB");
        }
        let leaves = match self.txs.body_txid_range(first.0, last) {
            Ok(v) if v.len() == count as usize => v,
            Ok(_) => {
                let _ = self.header_txs.clear_body(write, fk);
                report.bodies_cleared = report.bodies_cleared.saturating_add(1);
                return Err("txid.body short for header_txs range");
            }
            Err(_) => {
                let _ = self.header_txs.clear_body(write, fk);
                report.bodies_cleared = report.bodies_cleared.saturating_add(1);
                return Err("txid.body read");
            }
        };
        let root = merkle_root_from_txids(&leaves);
        if root != *merkle_root {
            let _ = self.header_txs.clear_body(write, fk);
            report.bodies_cleared = report.bodies_cleared.saturating_add(1);
            return Err("merkle root mismatch");
        }
        match self.strong_tx.all_strong_range(first, count) {
            Ok(true) => self.check_block_input_edges(write, fk, first.0, count, report),
            Ok(false) => Err("strong bits missing in tip window"),
            Err(_) => Err("strong_tx read"),
        }
    }

    /// Parent edges for one confirmed block. The first tx is the coinbase.
    ///
    /// A missing edge, a coinbase-shaped edge on a later tx, or a parent that
    /// is not an in-range output drops the block association and fails the
    /// window so the tip shrinks below that block. Seqsigwit count is skipped
    /// while that stem is pruned.
    #[doc(hidden)]
    pub fn check_block_input_edges(
        &self,
        write: &crate::array_table::ClassCWrite,
        header_fk: Fk,
        first: u64,
        count: u32,
        report: &mut TipRevalidateReport,
    ) -> Result<(), &'static str> {
        let reason = self.block_input_edge_reason(first, count);
        if let Err(reason) = reason {
            let _ = self.header_txs.clear_body(write, header_fk);
            report.bodies_cleared = report.bodies_cleared.saturating_add(1);
            return Err(reason);
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn block_input_edge_reason(&self, first: u64, count: u32) -> Result<(), &'static str> {
        if count == 0 {
            return Err("input edges short");
        }
        let last = first.saturating_add(u64::from(count)).saturating_sub(1);
        let spans = self
            .txs
            .input
            .edges_span(first, last)
            .map_err(|_| "input edges read")?;
        if spans.len() != count as usize {
            return Err("input edges short");
        }
        let prune = self.txs.prune_seqsigwit_mode();
        let mut parents: Vec<(Fk, u32)> = Vec::new();
        for (i, slot) in spans.iter().enumerate() {
            let Some(edges) = slot else {
                return Err("input unstamped");
            };
            if !prune {
                let n = self.seqsigwit_input_count(Fk(first + i as u64))?;
                if n != edges.len() {
                    return Err("input edge count");
                }
            }
            if i == 0 {
                let coinbase = edges.len() == 1 && edges[0].parent.is_null() && edges[0].vout == 0;
                if !coinbase {
                    return Err("coinbase input edge");
                }
                continue;
            }
            for edge in edges {
                if edge.parent.is_null() {
                    return Err("non-coinbase input edge");
                }
                parents.push((edge.parent, edge.vout));
            }
        }
        if parents.is_empty() {
            return Ok(());
        }
        let fks: Vec<Fk> = parents.iter().map(|(fk, _)| *fk).collect();
        let locs = self
            .txs
            .create_loc
            .range_batch(&fks)
            .map_err(|_| "input parent read")?;
        if locs.len() != parents.len() {
            return Err("input parent missing");
        }
        for ((_, vout), loc) in parents.iter().zip(locs.iter()) {
            let Some(pair) = loc else {
                return Err("input parent missing");
            };
            if *vout >= pair.n_out {
                return Err("input vout OOB");
            }
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn seqsigwit_input_count(&self, fk: Fk) -> Result<usize, &'static str> {
        let (off, len) = self
            .txs
            .seqsigwit_range(fk)
            .map_err(|_| "seqsigwit range")?;
        if len == 0 {
            return Ok(0);
        }
        let raw = self
            .txs
            .seqsigwit
            .with_bytes_at(off, len, |b| Ok(b.to_vec()))
            .map_err(|_| "seqsigwit read")?;
        crate::tx_table::decode_seqsigwit_secret_to_end(&raw, None)
            .map(|ins| ins.len())
            .map_err(|_| "seqsigwit decode")
    }

    /// Truncate confirmed tip to `last_good` (inclusive), or empty if `None`.
    #[doc(hidden)]
    pub fn shrink_tip_to(
        &self,
        write: &crate::array_table::ClassCWrite,
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
            self.confirmed.disconnect_tip(write, Height(cur))?;
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
        self.persist_class_c_repair()?;
        // Disconnect clamps in `Query`. Open revalidation shrinks here and
        // then replay treats a marker above the new tip as already annotated.
        self.clamp_spend_durable()?;
        report.tip_shrunk = true;
        report.tip_after = self.confirmed.tip_height().map(|h| h.0);
        Ok(())
    }

    /// The connect barrier may seal this tip. A withheld Class A header whose
    /// tip range ends past the locator count skips the flush. No header behind
    /// means the RAM count is the commit, including a Class C fixture.
    pub(crate) fn tip_fits_durable_creates(&self) -> Result<bool, StoreError> {
        if !self.txs.class_a_header_behind() {
            return Ok(true);
        }
        let covered = self.txs.durable_create_count()?;
        Ok(self.class_a_confirmed_cut(covered)?.is_none())
    }

    /// A sealed tip past the durable create count means the barrier wrote a
    /// height it does not allow. Class C fixtures have a tx range and no
    /// archive; they stay.
    pub(crate) fn refuse_sealed_tip_past_creates(&self) -> Result<(), StoreError> {
        let covered = self.txs.count();
        if self.class_a_confirmed_cut(covered)?.is_none() {
            return Ok(());
        }
        if covered == 0 && !self.txs.bodies_allocated_past_header() {
            return Ok(());
        }
        Err(StoreError::Corrupt(
            "invariant: sealed tip past durable creates",
        ))
    }

    /// Height a spend checkpoint may call durable, or `None` when no create is.
    pub(crate) fn spend_height_within_class_a(
        &self,
        height: u32,
    ) -> Result<Option<u32>, StoreError> {
        let covered = self.txs.durable_create_count()?;
        let Some(bad) = self.class_a_confirmed_cut(covered)? else {
            return Ok(Some(height));
        };
        Ok(bad.checked_sub(1).map(|good| good.min(height)))
    }

    /// First confirmed height whose tx range ends past `covered`, if any.
    fn class_a_confirmed_cut(&self, covered: u64) -> Result<Option<u32>, StoreError> {
        let Some(tip) = self.confirmed.tip_height() else {
            return Ok(None);
        };
        if let Some(end) = self.header_tx_end(tip)? {
            if end <= covered {
                return Ok(None);
            }
            return Ok(Some(self.first_height_past_creates(tip.0, covered)?));
        }
        if self.header_tx_end(Height(0))?.is_none() {
            return Ok(None);
        }
        let Some(last) = self.highest_height_with_tx_range(tip.0)? else {
            return Ok(None);
        };
        let Some(end) = self.header_tx_end(Height(last))? else {
            return Ok(None);
        };
        if end > covered {
            return Ok(Some(self.first_height_past_creates(last, covered)?));
        }
        if last < tip.0 {
            return Ok(Some(last + 1));
        }
        Ok(None)
    }

    fn header_tx_end(&self, height: Height) -> Result<Option<u64>, StoreError> {
        let Some(fk) = self.confirmed.get(height)? else {
            return Ok(None);
        };
        let Some((first, n)) = self.header_txs.get_range(fk)? else {
            return Ok(None);
        };
        if n == 0 || first.is_null() {
            return Ok(None);
        }
        Ok(Some(first.0.saturating_add(u64::from(n)).saturating_sub(1)))
    }

    /// `hi` itself ends past `covered`. Heights above `hi` are not searched.
    fn first_height_past_creates(&self, hi: u32, covered: u64) -> Result<u32, StoreError> {
        let mut lo = 0u32;
        let mut hi = hi;
        let mut found = hi;
        loop {
            let mid = lo + (hi - lo) / 2;
            let past = self
                .header_tx_end(Height(mid))?
                .is_some_and(|end| end > covered);
            if past {
                found = mid;
                if mid == lo {
                    break;
                }
                hi = mid - 1;
            } else if mid == hi {
                break;
            } else {
                lo = mid + 1;
            }
        }
        Ok(found)
    }

    fn highest_height_with_tx_range(&self, tip: u32) -> Result<Option<u32>, StoreError> {
        if self.header_tx_end(Height(tip))?.is_some() {
            return Ok(Some(tip));
        }
        let mut lo = 0u32;
        let mut hi = tip;
        let mut found = None;
        loop {
            let mid = lo + (hi - lo) / 2;
            if self.header_tx_end(Height(mid))?.is_some() {
                found = Some(mid);
                if mid == tip {
                    break;
                }
                lo = mid + 1;
            } else if mid == 0 {
                break;
            } else {
                hi = mid - 1;
            }
            if lo > hi {
                break;
            }
        }
        Ok(found)
    }

    #[doc(hidden)]
    pub fn persist_class_c_repair(&self) -> Result<(), StoreError> {
        let n = self.repair_class_c_above_tip()?;
        if n > 0 {
            self.strong_tx.flush()?;
        }
        Ok(())
    }
}
