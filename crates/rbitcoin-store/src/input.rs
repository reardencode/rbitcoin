//! Spender → parent edges (`input.loc` / `input.off` / `input.body`).
//!
//! `input.loc` is `n_in` as u16 LE per create (`0` = unstamped). `input.body`
//! is 8 bytes per input in vin order: parent `create_fk` u40 LE, parent vout
//! u24 LE. `input.off` checkpoints the body file offset at each 1024-create
//! window after the first.

use crate::delta_loc::{checkpoint_prefix, loc_window, loc_within, LOC_WINDOW};
use crate::error::StoreError;
use crate::file::{TableFile, FILE_HEADER_LEN};
use rbitcoin_primitives::{Fk, TableKind};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

#[doc(hidden)]
pub const LOC_SLOT: u64 = 2;
#[doc(hidden)]
pub const OFF_SLOT: u64 = 8;
#[doc(hidden)]
pub const REC_LEN: u64 = 8;
#[doc(hidden)]
pub const FK_LIMIT: u64 = 1 << 40;
#[doc(hidden)]
pub const VOUT_LIMIT: u32 = 1 << 24;

/// One spending input's parent outpoint. `parent` null and `vout` 0 is coinbase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputEdge {
    pub parent: Fk,
    pub vout: u32,
}

impl InputEdge {
    pub fn coinbase() -> Self {
        Self {
            parent: Fk::NULL,
            vout: 0,
        }
    }

    pub fn pack(self) -> Result<[u8; 8], StoreError> {
        if self.parent.0 >= FK_LIMIT {
            return Err(StoreError::Corrupt("input create_fk"));
        }
        if self.vout >= VOUT_LIMIT {
            return Err(StoreError::Corrupt("input vout"));
        }
        if self.parent.is_null() && self.vout != 0 {
            return Err(StoreError::Corrupt("input coinbase vout"));
        }
        let mut b = [0u8; 8];
        let fk = self.parent.0.to_le_bytes();
        b[..5].copy_from_slice(&fk[..5]);
        let v = self.vout.to_le_bytes();
        b[5] = v[0];
        b[6] = v[1];
        b[7] = v[2];
        Ok(b)
    }

    pub fn unpack(b: [u8; 8]) -> Result<Self, StoreError> {
        let mut fk_b = [0u8; 8];
        fk_b[..5].copy_from_slice(&b[..5]);
        let parent = Fk(u64::from_le_bytes(fk_b));
        let vout = u32::from(b[5]) | (u32::from(b[6]) << 8) | (u32::from(b[7]) << 16);
        let edge = Self { parent, vout };
        if parent.is_null() && vout != 0 {
            return Err(StoreError::Corrupt("input coinbase vout"));
        }
        Ok(edge)
    }
}

pub struct Input {
    pub loc: TableFile,
    pub off: TableFile,
    pub body: TableFile,
    /// Body file offset at the start of window `w + 1` (after create `1024*(w+1)`).
    pub checkpoints: RwLock<Vec<u64>>,
    pub count: AtomicU64,
    pub body_end: AtomicU64,
}

impl Input {
    pub fn flush(&self) -> Result<(), StoreError> {
        self.loc.flush()?;
        self.off.flush()?;
        self.body.flush()?;
        Ok(())
    }

    pub fn sync_data_only(&self) -> Result<(), StoreError> {
        self.loc.sync_data_only()?;
        self.off.sync_data_only()?;
        self.body.sync_data_only()
    }

    #[cfg(debug_assertions)]
    pub fn pending_sync(&self) -> bool {
        self.loc.pending_sync() || self.off.pending_sync() || self.body.pending_sync()
    }

    pub fn create(dir: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            loc: TableFile::create(dir.join("input.loc"), TableKind::InputLoc)?,
            off: TableFile::create(dir.join("input.off"), TableKind::ArrayLink)?,
            body: TableFile::create(dir.join("input.body"), TableKind::Input)?,
            checkpoints: RwLock::new(Vec::new()),
            count: AtomicU64::new(0),
            body_end: AtomicU64::new(FILE_HEADER_LEN as u64),
        })
    }

    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        let loc = TableFile::open(dir.join("input.loc"), TableKind::InputLoc)?;
        let off = TableFile::open(dir.join("input.off"), TableKind::ArrayLink)?;
        let body = TableFile::open(dir.join("input.body"), TableKind::Input)?;
        let loc_data = loc.data_len();
        if loc_data % LOC_SLOT != 0 {
            return Err(StoreError::Corrupt("invariant: input.loc size"));
        }
        let full = loc_data / LOC_SLOT;
        let Some(count) = checkpoint_prefix(full, off.data_len(), OFF_SLOT) else {
            return Err(StoreError::Corrupt("invariant: input.off size"));
        };
        let n_win = count / LOC_WINDOW;
        let body_len = body.logical_len();
        if body_len < FILE_HEADER_LEN as u64
            || !(body_len - FILE_HEADER_LEN as u64).is_multiple_of(REC_LEN)
        {
            return Err(StoreError::Corrupt("invariant: input.body size"));
        }
        let mut checkpoints = vec![0u64; n_win as usize];
        if n_win > 0 {
            let mut bytes = vec![0u8; (n_win * OFF_SLOT) as usize];
            off.read_at(FILE_HEADER_LEN as u64, &mut bytes)?;
            for (i, chunk) in bytes.chunks_exact(OFF_SLOT as usize).enumerate() {
                checkpoints[i] = u64::from_le_bytes(chunk.try_into().unwrap());
            }
        }
        let opened = Self {
            loc,
            off,
            body,
            checkpoints: RwLock::new(checkpoints),
            count: AtomicU64::new(full),
            body_end: AtomicU64::new(body_len),
        };
        if count < full {
            opened.truncate_to_count(count)?;
        } else {
            let need = FILE_HEADER_LEN as u64 + n_win * OFF_SLOT;
            if opened.off.logical_len() > need {
                opened.off.set_logical_len(need)?;
            }
        }
        Ok(opened)
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Acquire)
    }

    /// `None` when the create is unstamped (`n_in == 0`).
    pub fn n_in(&self, fk: Fk) -> Result<Option<u32>, StoreError> {
        let id = self.checked_id(fk)?;
        let n = self.read_n_in(id)?;
        Ok(if n == 0 { None } else { Some(u32::from(n)) })
    }

    /// Parent edges for contiguous creates `first..=last` (1-based ids).
    ///
    /// One locator pread (from the window start, for the body offset) and one
    /// body pread. `None` is unstamped.
    pub fn edges_span(
        &self,
        first: u64,
        last: u64,
    ) -> Result<Vec<Option<Vec<InputEdge>>>, StoreError> {
        let mut plan = self.plan_edges_span(first, last)?;
        self.loc.read_at(plan.loc_off, &mut plan.loc)?;
        let (abs, len) = self.edges_body_read(&plan)?;
        let mut body = vec![0u8; len as usize];
        if len > 0 {
            self.body.read_at(abs, &mut body)?;
        }
        decode_edges_span(&plan, &body)
    }

    /// Locator read for [`Self::edges_span`]: `n_in` from the window start of
    /// `first` through `last` (no IO).
    pub fn plan_edges_span(&self, first: u64, last: u64) -> Result<EdgesPlan, StoreError> {
        if first == 0 || last < first {
            return Err(StoreError::InvalidFk);
        }
        if last > self.count() {
            return Err(StoreError::NotFound);
        }
        let w = loc_window(first);
        let win_first = w * LOC_WINDOW + 1;
        let base = if w == 0 {
            FILE_HEADER_LEN as u64
        } else {
            let cps = self.checkpoints.read().unwrap_or_else(|e| e.into_inner());
            *cps.get((w - 1) as usize)
                .ok_or(StoreError::Corrupt("invariant: input.off checkpoint"))?
        };
        Ok(EdgesPlan {
            base,
            skip: (first - win_first) as usize,
            loc_off: FILE_HEADER_LEN as u64 + (win_first - 1) * LOC_SLOT,
            loc: vec![0u8; (last - win_first + 1) as usize * LOC_SLOT as usize],
        })
    }

    /// Body read `(abs, len)` for a plan whose locator bytes are filled.
    pub fn edges_body_read(&self, plan: &EdgesPlan) -> Result<(u64, u64), StoreError> {
        let n_in = |c: &[u8]| u64::from(u16::from_le_bytes([c[0], c[1]]));
        let mut slots = plan.loc.chunks_exact(LOC_SLOT as usize);
        let before: u64 = slots.by_ref().take(plan.skip).map(n_in).sum();
        let span: u64 = slots.map(n_in).sum();
        Ok((plan.base + before * REC_LEN, span * REC_LEN))
    }

    /// `input.loc` / `input.body` handles and paths for a machine's reads.
    pub fn files(
        &self,
    ) -> (
        (crate::io_handle::IoHandle, &Path),
        (crate::io_handle::IoHandle, &Path),
    ) {
        (
            (self.loc.read_fd(), self.loc.path()),
            (self.body.read_fd(), self.body.path()),
        )
    }

    /// Parent edges in vin order. `None` when unstamped.
    pub fn edges(&self, fk: Fk) -> Result<Option<Vec<InputEdge>>, StoreError> {
        let Some(n) = self.n_in(fk)? else {
            return Ok(None);
        };
        let id = fk.get().ok_or(StoreError::InvalidFk)?;
        let abs = self.body_abs(id)?;
        let mut raw = vec![0u8; n as usize * REC_LEN as usize];
        self.body.read_at(abs, &mut raw)?;
        let mut out = Vec::with_capacity(n as usize);
        for chunk in raw.chunks_exact(REC_LEN as usize) {
            let mut b = [0u8; 8];
            b.copy_from_slice(chunk);
            out.push(InputEdge::unpack(b)?);
        }
        Ok(Some(out))
    }

    pub fn append(&self, txs: &[Vec<InputEdge>]) -> Result<(), StoreError> {
        if txs.is_empty() {
            return Ok(());
        }
        let base = self.count.load(Ordering::Acquire);
        let mut loc_bytes = Vec::with_capacity(txs.len() * 2);
        let mut body_bytes = Vec::new();
        let mut new_offs: Vec<(u64, u64)> = Vec::new();
        let mut body_at = self.body_end.load(Ordering::Acquire);
        for (i, edges) in txs.iter().enumerate() {
            if edges.len() > usize::from(u16::MAX) {
                return Err(StoreError::Corrupt("input n_in"));
            }
            let n_in = edges.len() as u16;
            let fk = base + 1 + i as u64;
            loc_bytes.extend_from_slice(&n_in.to_le_bytes());
            for edge in edges {
                body_bytes.extend_from_slice(&edge.pack()?);
            }
            body_at = body_at.saturating_add(u64::from(n_in) * REC_LEN);
            if fk.is_multiple_of(LOC_WINDOW) {
                new_offs.push((fk / LOC_WINDOW - 1, body_at));
            }
        }
        let loc_at = FILE_HEADER_LEN as u64 + base * LOC_SLOT;
        self.loc.write_at(loc_at, &loc_bytes)?;
        if !body_bytes.is_empty() {
            let body_start = self.body_end.load(Ordering::Acquire);
            self.body.write_at(body_start, &body_bytes)?;
        }
        if !new_offs.is_empty() {
            {
                let cps = self.checkpoints.read().unwrap_or_else(|e| e.into_inner());
                if new_offs[0].0 as usize != cps.len() {
                    return Err(StoreError::Corrupt("invariant: input.off index"));
                }
            }
            let mut blob = Vec::with_capacity(new_offs.len() * OFF_SLOT as usize);
            for &(_, abs) in &new_offs {
                blob.extend_from_slice(&abs.to_le_bytes());
            }
            let off_at = FILE_HEADER_LEN as u64 + new_offs[0].0 * OFF_SLOT;
            self.off.write_at(off_at, &blob)?;
            let mut cps = self.checkpoints.write().unwrap_or_else(|e| e.into_inner());
            for &(w, abs) in &new_offs {
                if w as usize != cps.len() {
                    return Err(StoreError::Corrupt("invariant: input.off index"));
                }
                cps.push(abs);
            }
        }
        self.body_end.store(body_at, Ordering::Release);
        self.count.store(base + txs.len() as u64, Ordering::Release);
        Ok(())
    }

    pub fn truncate_to_count(&self, new_count: u64) -> Result<(), StoreError> {
        let cur = self.count.load(Ordering::Acquire);
        if new_count > cur {
            return Err(StoreError::Corrupt("input.loc truncate past count"));
        }
        if new_count == cur {
            return Ok(());
        }
        let dropped = (cur - new_count) as usize;
        let mut raw = vec![0u8; dropped * LOC_SLOT as usize];
        let at = FILE_HEADER_LEN as u64 + new_count * LOC_SLOT;
        self.loc.read_at(at, &mut raw)?;
        let mut n_drop = 0u64;
        for chunk in raw.chunks_exact(LOC_SLOT as usize) {
            n_drop += u64::from(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        let body_end = self.body_end.load(Ordering::Acquire);
        let new_body = body_end - n_drop * REC_LEN;
        if new_body < FILE_HEADER_LEN as u64 {
            return Err(StoreError::Corrupt("invariant: input.body truncate"));
        }
        let n_win = new_count / LOC_WINDOW;
        // Checkpoint before the loc header, same crash window as create.loc.
        self.off
            .set_logical_len(FILE_HEADER_LEN as u64 + n_win * OFF_SLOT)?;
        self.body.set_logical_len(new_body)?;
        self.loc
            .set_logical_len(FILE_HEADER_LEN as u64 + new_count * LOC_SLOT)?;
        {
            let mut cps = self.checkpoints.write().unwrap_or_else(|e| e.into_inner());
            cps.truncate(n_win as usize);
        }
        self.body_end.store(new_body, Ordering::Release);
        self.count.store(new_count, Ordering::Release);
        Ok(())
    }

    #[doc(hidden)]
    pub fn checked_id(&self, fk: Fk) -> Result<u64, StoreError> {
        let Some(id) = fk.get() else {
            return Err(StoreError::InvalidFk);
        };
        if id > self.count.load(Ordering::Acquire) {
            return Err(StoreError::NotFound);
        }
        Ok(id)
    }

    #[doc(hidden)]
    pub fn read_n_in(&self, id: u64) -> Result<u16, StoreError> {
        let mut buf = [0u8; 2];
        self.loc
            .read_at(FILE_HEADER_LEN as u64 + (id - 1) * LOC_SLOT, &mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    #[doc(hidden)]
    pub fn body_abs(&self, id: u64) -> Result<u64, StoreError> {
        let w = loc_window(id);
        let within = loc_within(id);
        let base = if w == 0 {
            FILE_HEADER_LEN as u64
        } else {
            let cps = self.checkpoints.read().unwrap_or_else(|e| e.into_inner());
            *cps.get((w - 1) as usize)
                .ok_or(StoreError::Corrupt("invariant: input.off checkpoint"))?
        };
        if within == 0 {
            return Ok(base);
        }
        let win_first = w * LOC_WINDOW;
        let mut raw = vec![0u8; within * LOC_SLOT as usize];
        self.loc
            .read_at(FILE_HEADER_LEN as u64 + win_first * LOC_SLOT, &mut raw)?;
        let mut n = 0u64;
        for chunk in raw.chunks_exact(LOC_SLOT as usize) {
            n += u64::from(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        Ok(base + n * REC_LEN)
    }
}

/// Locator read of one [`Input::plan_edges_span`].
pub struct EdgesPlan {
    pub base: u64,
    pub skip: usize,
    pub loc_off: u64,
    pub loc: Vec<u8>,
}

/// Edges per create of a filled plan and its body bytes.
pub fn decode_edges_span(
    plan: &EdgesPlan,
    body: &[u8],
) -> Result<Vec<Option<Vec<InputEdge>>>, StoreError> {
    let mut out = Vec::new();
    let mut off = 0usize;
    for chunk in plan.loc.chunks_exact(LOC_SLOT as usize).skip(plan.skip) {
        let n_in = u16::from_le_bytes([chunk[0], chunk[1]]) as usize;
        if n_in == 0 {
            out.push(None);
            continue;
        }
        let len = n_in * REC_LEN as usize;
        let slice = body
            .get(off..off + len)
            .ok_or(StoreError::Corrupt("invariant: input.body span short"))?;
        let mut edges = Vec::with_capacity(n_in);
        for rec in slice.chunks_exact(REC_LEN as usize) {
            let mut b = [0u8; REC_LEN as usize];
            b.copy_from_slice(rec);
            edges.push(InputEdge::unpack(b)?);
        }
        off += len;
        out.push(Some(edges));
    }
    Ok(out)
}
