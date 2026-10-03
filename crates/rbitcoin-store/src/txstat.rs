//! Dense **create_fk-ordered** confirm-time econ (`txstat.body`).
//!
//! Layout (schema 25):
//! ```text
//! txstat.body  offset 0..32              — TableFile 16 + 16 pad
//!              offset 32+(fk-1)×8        — 8-byte cell
//! txstat.ovf   append-only tails          — remaining ULEB bytes when the
//!                                          four-field stream exceeds 8 B
//! txstat.blk   offset 32+(header_fk-1)×16 — off:u64, len:u32, n_ovf:u32
//! ```
//!
//! Cell payload is three canonical ULEBs: `fee_sat`, `base` (non-witness
//! size), `wit_extra` (`total_size − base`). `n_in` lives on `input.loc`.
//! `size = base + wit_extra`, `weight = 4×base + wit_extra`. All-zero cell =
//! unstamped. A truncated ULEB or fewer than three fields means the rest of
//! the stream is in that header's overflow blob (`encoded[8..]`). Pin / SH /
//! tweaks do not open these files.

use crate::error::StoreError;
use crate::file::{GrowPolicy, TableFile, FILE_HEADER_LEN};
use rbitcoin_primitives::{read_uleb128, uleb128_len, write_uleb128, Fk, TableKind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Bytes before first body cell (TableFile header 16 + pad to 32).
pub const TXSTAT_BODY_HEADER: u64 = 32;
pub const TXSTAT_ENTRY_LEN: u64 = 8;
const BLK_HEADER: u64 = 32;
const BLK_SLOT: u64 = 16;
/// Overflow blob ceiling. A longer on-disk length is corrupt, not an allocation.
const TXSTAT_BLOB_CEILING: usize = 16 * 1024 * 1024;

fn checked_blob_len(len: usize, remain: u64) -> Result<usize, StoreError> {
    if len > TXSTAT_BLOB_CEILING || (len as u64) > remain {
        return Err(StoreError::Corrupt("invariant: txstat blob length"));
    }
    Ok(len)
}

/// Packed confirm-time econ. All-zero on disk is unstamped (not this struct).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxStatRow {
    pub fee_sat: u64,
    pub base: u32,
    pub wit_extra: u32,
}

impl TxStatRow {
    pub fn size(&self) -> u64 {
        u64::from(self.base).saturating_add(u64::from(self.wit_extra))
    }

    pub fn weight(&self) -> u64 {
        u64::from(self.base)
            .saturating_mul(4)
            .saturating_add(u64::from(self.wit_extra))
    }

    pub fn has_witness(&self) -> bool {
        self.wit_extra != 0
    }
}

pub fn encode_stream(row: &TxStatRow) -> Result<Vec<u8>, StoreError> {
    let mut v = Vec::new();
    write_uleb128(&mut v, row.fee_sat);
    write_uleb128(&mut v, u64::from(row.base));
    write_uleb128(&mut v, u64::from(row.wit_extra));
    Ok(v)
}

pub fn pack_cell(row: &TxStatRow) -> Result<([u8; 8], Option<Vec<u8>>), StoreError> {
    let s = encode_stream(row)?;
    let mut cell = [0u8; 8];
    if s.len() <= 8 {
        cell[..s.len()].copy_from_slice(&s);
        Ok((cell, None))
    } else {
        cell.copy_from_slice(&s[..8]);
        Ok((cell, Some(s[8..].to_vec())))
    }
}

fn read_canonical_uleb(buf: &[u8]) -> Result<(u64, usize), StoreError> {
    let (v, n) = read_uleb128(buf).map_err(|e| StoreError::Corrupt(e.0))?;
    if n != uleb128_len(v) {
        return Err(StoreError::Corrupt("txstat uleb overlong"));
    }
    Ok((v, n))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellParse {
    Unstamped,
    Complete(TxStatRow),
    NeedTail,
}

pub fn parse_cell(cell: [u8; 8]) -> Result<CellParse, StoreError> {
    if cell == [0u8; 8] {
        return Ok(CellParse::Unstamped);
    }
    match parse_stream(&cell, true)? {
        StreamParse::Complete(row) => Ok(CellParse::Complete(row)),
        StreamParse::NeedMore => Ok(CellParse::NeedTail),
    }
}

enum StreamParse {
    Complete(TxStatRow),
    NeedMore,
}

fn parse_stream(buf: &[u8], allow_trunc: bool) -> Result<StreamParse, StoreError> {
    let mut off = 0usize;
    let mut fields = [0u64; 3];
    for slot in &mut fields {
        if off >= buf.len() {
            if allow_trunc {
                return Ok(StreamParse::NeedMore);
            }
            return Err(StoreError::Corrupt("txstat uleb truncated"));
        }
        match read_canonical_uleb(&buf[off..]) {
            Ok((v, n)) => {
                *slot = v;
                off += n;
            }
            Err(StoreError::Corrupt("uleb128 truncated")) if allow_trunc => {
                return Ok(StreamParse::NeedMore);
            }
            Err(e) => return Err(e),
        }
    }
    if buf[off..].iter().any(|&b| b != 0) {
        return Err(StoreError::Corrupt("txstat cell trailing non-zero"));
    }
    let base = u32::try_from(fields[1]).map_err(|_| StoreError::Corrupt("txstat base"))?;
    let wit_extra =
        u32::try_from(fields[2]).map_err(|_| StoreError::Corrupt("txstat wit_extra"))?;
    Ok(StreamParse::Complete(TxStatRow {
        fee_sat: fields[0],
        base,
        wit_extra,
    }))
}

pub fn parse_with_tail(cell: [u8; 8], tail: &[u8]) -> Result<TxStatRow, StoreError> {
    let mut buf = Vec::with_capacity(8 + tail.len());
    buf.extend_from_slice(&cell);
    buf.extend_from_slice(tail);
    match parse_stream(&buf, false)? {
        StreamParse::Complete(row) => Ok(row),
        StreamParse::NeedMore => Err(StoreError::Corrupt("invariant: txstat overflow missing")),
    }
}

pub fn encode_ovf_blob(tails: &[(u16, Vec<u8>)]) -> Result<Vec<u8>, StoreError> {
    let mut out = Vec::new();
    for (idx, rest) in tails {
        if rest.is_empty() {
            return Err(StoreError::Corrupt("txstat overflow empty tail"));
        }
        if rest.len() > 255 {
            return Err(StoreError::Corrupt("txstat overflow tail"));
        }
        out.extend_from_slice(&idx.to_le_bytes());
        out.push(rest.len() as u8);
        out.extend_from_slice(rest);
    }
    Ok(out)
}

pub fn decode_ovf_blob(raw: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, StoreError> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < raw.len() {
        if raw.len() - off < 3 {
            return Err(StoreError::Corrupt("txstat overflow short"));
        }
        let idx = u16::from_le_bytes([raw[off], raw[off + 1]]);
        let n = raw[off + 2] as usize;
        off += 3;
        if n == 0 || off + n > raw.len() {
            return Err(StoreError::Corrupt("txstat overflow tail"));
        }
        out.push((idx, raw[off..off + n].to_vec()));
        off += n;
    }
    Ok(out)
}

fn tail_for_index(tails: &[(u16, Vec<u8>)], idx: u16) -> Result<&[u8], StoreError> {
    match tails.binary_search_by_key(&idx, |(i, _)| *i) {
        Ok(p) => Ok(tails[p].1.as_slice()),
        Err(_) => Err(StoreError::Corrupt("invariant: txstat overflow missing")),
    }
}

/// Dense 8 B/create body plus per-header overflow tails.
pub struct TxStat {
    body: TableFile,
    ovf: TableFile,
    blk: TableFile,
    count: AtomicU64,
    ovf_len: AtomicU64,
}

impl TxStat {
    pub(crate) fn flush(&self) -> Result<(), StoreError> {
        self.body.flush()?;
        self.ovf.flush()?;
        self.blk.flush()?;
        Ok(())
    }

    pub(crate) fn sync_data_only(&self) -> Result<(), StoreError> {
        self.body.sync_data_only()?;
        self.ovf.sync_data_only()?;
        self.blk.sync_data_only()
    }

    #[cfg(test)]
    pub(crate) fn pending_sync(&self) -> bool {
        self.body.pending_sync() || self.ovf.pending_sync() || self.blk.pending_sync()
    }

    pub fn create(dir: &Path) -> Result<Self, StoreError> {
        let body = TableFile::create(Self::body_path(dir), TableKind::TxStat)?;
        let pad = vec![0u8; (TXSTAT_BODY_HEADER as usize).saturating_sub(FILE_HEADER_LEN)];
        if !pad.is_empty() {
            body.write_at_pwrite(FILE_HEADER_LEN as u64, &pad)?;
        }
        let ovf = TableFile::create(Self::ovf_path(dir), TableKind::TxStatOvf)?;
        ovf.set_grow_policy(GrowPolicy::Tight1MiB);
        let blk = TableFile::create(Self::blk_path(dir), TableKind::TxStatBlk)?;
        blk.set_grow_policy(GrowPolicy::Tight1MiB);
        let bpad = vec![0u8; (BLK_HEADER as usize).saturating_sub(FILE_HEADER_LEN)];
        if !bpad.is_empty() {
            blk.write_at_pwrite(FILE_HEADER_LEN as u64, &bpad)?;
        }
        Ok(Self {
            body,
            ovf,
            blk,
            count: AtomicU64::new(0),
            ovf_len: AtomicU64::new(0),
        })
    }

    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        let leftover = dir.join("txfixed.body");
        if leftover.exists() {
            std::fs::remove_file(&leftover).map_err(|e| StoreError::io(&leftover, e))?;
        }
        let body_path = Self::body_path(dir);
        let body = if body_path.exists() {
            TableFile::open(body_path, TableKind::TxStat)?
        } else {
            let b = TableFile::create(&body_path, TableKind::TxStat)?;
            let pad = vec![0u8; (TXSTAT_BODY_HEADER as usize).saturating_sub(FILE_HEADER_LEN)];
            if !pad.is_empty() {
                b.write_at_pwrite(FILE_HEADER_LEN as u64, &pad)?;
            }
            b
        };
        let len = body.logical_len();
        let count = if len <= TXSTAT_BODY_HEADER {
            0
        } else {
            (len - TXSTAT_BODY_HEADER) / TXSTAT_ENTRY_LEN
        };
        let ovf_path = Self::ovf_path(dir);
        let ovf = if ovf_path.exists() {
            let f = TableFile::open(ovf_path, TableKind::TxStatOvf)?;
            f.set_grow_policy(GrowPolicy::Tight1MiB);
            f
        } else {
            let f = TableFile::create(&ovf_path, TableKind::TxStatOvf)?;
            f.set_grow_policy(GrowPolicy::Tight1MiB);
            f
        };
        let ovf_len = ovf.data_len();
        let blk_path = Self::blk_path(dir);
        let blk = if blk_path.exists() {
            let f = TableFile::open(blk_path, TableKind::TxStatBlk)?;
            f.set_grow_policy(GrowPolicy::Tight1MiB);
            f
        } else {
            let f = TableFile::create(&blk_path, TableKind::TxStatBlk)?;
            f.set_grow_policy(GrowPolicy::Tight1MiB);
            let bpad = vec![0u8; (BLK_HEADER as usize).saturating_sub(FILE_HEADER_LEN)];
            if !bpad.is_empty() {
                f.write_at_pwrite(FILE_HEADER_LEN as u64, &bpad)?;
            }
            f
        };
        Ok(Self {
            body,
            ovf,
            blk,
            count: AtomicU64::new(count),
            ovf_len: AtomicU64::new(ovf_len),
        })
    }

    fn body_path(dir: &Path) -> PathBuf {
        dir.join("txstat.body")
    }
    fn ovf_path(dir: &Path) -> PathBuf {
        dir.join("txstat.ovf")
    }
    fn blk_path(dir: &Path) -> PathBuf {
        dir.join("txstat.blk")
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Acquire)
    }

    pub fn truncate_to_count(&self, new_count: u64) -> Result<(), StoreError> {
        let cur = self.count();
        if new_count > cur {
            return Err(StoreError::Corrupt("txstat.body truncate past count"));
        }
        if new_count == cur {
            return Ok(());
        }
        let new_len = TXSTAT_BODY_HEADER + new_count * TXSTAT_ENTRY_LEN;
        self.body.set_logical_len(new_len)?;
        self.count.store(new_count, Ordering::Release);
        Ok(())
    }

    pub fn extend_or_truncate_to(&self, new_count: u64) -> Result<(), StoreError> {
        let cur = self.count();
        if new_count == cur {
            return Ok(());
        }
        if new_count < cur {
            return self.truncate_to_count(new_count);
        }
        let new_len = TXSTAT_BODY_HEADER + new_count * TXSTAT_ENTRY_LEN;
        self.body.set_logical_len(new_len)?;
        self.count.store(new_count, Ordering::Release);
        Ok(())
    }

    #[inline]
    pub fn entry_offset(fk: u64) -> Result<u64, StoreError> {
        if fk == 0 {
            return Err(StoreError::InvalidFk);
        }
        Ok(TXSTAT_BODY_HEADER + (fk - 1) * TXSTAT_ENTRY_LEN)
    }

    pub fn get_cell(&self, fk: Fk) -> Result<[u8; 8], StoreError> {
        let id = fk.get().ok_or(StoreError::InvalidFk)?;
        if id > self.count() {
            return Err(StoreError::NotFound);
        }
        let off = Self::entry_offset(id)?;
        let mut buf = [0u8; 8];
        self.body.read_at(off, &mut buf)?;
        Ok(buf)
    }

    pub fn get_row_merged(
        &self,
        fk: Fk,
        first_fk: u64,
        blob: &[u8],
    ) -> Result<Option<TxStatRow>, StoreError> {
        let cell = self.get_cell(fk)?;
        match parse_cell(cell)? {
            CellParse::Unstamped => Ok(None),
            CellParse::Complete(row) => Ok(Some(row)),
            CellParse::NeedTail => {
                let id = fk.get().ok_or(StoreError::InvalidFk)?;
                if id < first_fk {
                    return Err(StoreError::Corrupt("invariant: txstat overflow missing"));
                }
                let idx = u16::try_from(id - first_fk)
                    .map_err(|_| StoreError::Corrupt("txstat overflow index"))?;
                let tails = decode_ovf_blob(blob)?;
                let rest = tail_for_index(&tails, idx)?;
                Ok(Some(parse_with_tail(cell, rest)?))
            }
        }
    }

    pub fn get_range(
        &self,
        first: u64,
        last: u64,
        blob: Option<&[u8]>,
    ) -> Result<Vec<Option<TxStatRow>>, StoreError> {
        if last < first {
            return Ok(Vec::new());
        }
        let n = self.count();
        if first == 0 || last > n {
            return Err(StoreError::NotFound);
        }
        let count = (last - first + 1) as usize;
        let off = Self::entry_offset(first)?;
        let mut raw = vec![0u8; count * TXSTAT_ENTRY_LEN as usize];
        let rc = crate::bulk_io::pread_single(self.body.read_fd(), off, &mut raw);
        if rc < 0 {
            return Err(StoreError::io(
                self.body.path(),
                std::io::Error::from_raw_os_error(-rc),
            ));
        }
        if (rc as usize) != raw.len() {
            self.body.pread_at(off, &mut raw)?;
        }
        let tails = match blob {
            Some(b) if !b.is_empty() => decode_ovf_blob(b)?,
            _ => Vec::new(),
        };
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let s = i * TXSTAT_ENTRY_LEN as usize;
            let cell: [u8; 8] = raw[s..s + 8].try_into().unwrap();
            match parse_cell(cell)? {
                CellParse::Unstamped => out.push(None),
                CellParse::Complete(row) => out.push(Some(row)),
                CellParse::NeedTail => {
                    let idx = u16::try_from(i)
                        .map_err(|_| StoreError::Corrupt("txstat overflow index"))?;
                    let rest = tail_for_index(&tails, idx)?;
                    out.push(Some(parse_with_tail(cell, rest)?));
                }
            }
        }
        Ok(out)
    }

    pub fn append_batch(
        &self,
        base_count: u64,
        rows: &[TxStatRow],
    ) -> Result<Vec<(u64, Vec<u8>)>, StoreError> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let cur = self.count.load(Ordering::Acquire);
        if cur != base_count {
            return Err(StoreError::Corrupt("txstat.body count mismatch on append"));
        }
        let start = TXSTAT_BODY_HEADER + base_count * TXSTAT_ENTRY_LEN;
        let mut blob = Vec::with_capacity(rows.len() * TXSTAT_ENTRY_LEN as usize);
        let mut tails = Vec::new();
        for (i, row) in rows.iter().enumerate() {
            let (cell, tail) = pack_cell(row)?;
            blob.extend_from_slice(&cell);
            if let Some(t) = tail {
                tails.push((base_count + 1 + i as u64, t));
            }
        }
        self.body.write_at_pwrite(start, &blob)?;
        let new = base_count + rows.len() as u64;
        self.count.store(new, Ordering::Release);
        Ok(tails)
    }

    pub fn write_row(&self, fk: Fk, row: &TxStatRow) -> Result<(), StoreError> {
        let id = fk.get().ok_or(StoreError::InvalidFk)?;
        if id > self.count() {
            return Err(StoreError::NotFound);
        }
        let (cell, tail) = pack_cell(row)?;
        if tail.is_some() {
            return Err(StoreError::Corrupt("txstat overflow needs header blob"));
        }
        let off = Self::entry_offset(id)?;
        self.body.write_at_pwrite(off, &cell)?;
        Ok(())
    }

    pub fn write_block_rows(
        &self,
        header_fk: Fk,
        first_fk: u64,
        rows: &[TxStatRow],
    ) -> Result<(), StoreError> {
        if rows.is_empty() {
            return self.put_header_blob(header_fk, &[]);
        }
        let last = first_fk
            .checked_add(rows.len() as u64 - 1)
            .ok_or(StoreError::Corrupt("txstat block last fk"))?;
        if last > self.count() {
            return Err(StoreError::NotFound);
        }
        let start = Self::entry_offset(first_fk)?;
        let mut blob = Vec::with_capacity(rows.len() * 8);
        let mut tails = Vec::new();
        for (i, row) in rows.iter().enumerate() {
            let (cell, tail) = pack_cell(row)?;
            blob.extend_from_slice(&cell);
            if let Some(t) = tail {
                let idx =
                    u16::try_from(i).map_err(|_| StoreError::Corrupt("txstat overflow index"))?;
                tails.push((idx, t));
            }
        }
        self.body.write_at_pwrite(start, &blob)?;
        let raw = encode_ovf_blob(&tails)?;
        self.put_header_blob(header_fk, &raw)
    }

    pub fn put_overflows_for_headers(
        &self,
        ranges: &[(Fk, Fk, u32)],
        tails: &[(u64, Vec<u8>)],
    ) -> Result<(), StoreError> {
        if ranges.is_empty() {
            if !tails.is_empty() {
                return Err(StoreError::Corrupt("txstat overflow without header"));
            }
            return Ok(());
        }
        for &(hfk, first, n) in ranges {
            let Some(first_id) = first.get() else {
                continue;
            };
            let last = first_id.saturating_add(u64::from(n.saturating_sub(1)));
            let mut chunk = Vec::new();
            for (fk, rest) in tails {
                if *fk < first_id || *fk > last {
                    continue;
                }
                let idx = u16::try_from(*fk - first_id)
                    .map_err(|_| StoreError::Corrupt("txstat overflow index"))?;
                chunk.push((idx, rest.clone()));
            }
            if chunk.is_empty() {
                continue;
            }
            let raw = encode_ovf_blob(&chunk)?;
            self.put_header_blob(hfk, &raw)?;
        }
        Ok(())
    }

    pub fn put_header_blob(&self, header_fk: Fk, blob: &[u8]) -> Result<(), StoreError> {
        let hfk = header_fk.get().ok_or(StoreError::InvalidFk)?;
        let (off, len, n) = if blob.is_empty() {
            (0u64, 0u32, 0u32)
        } else {
            let at = FILE_HEADER_LEN as u64 + self.ovf_len.load(Ordering::Acquire);
            self.ovf.write_at_pwrite(at, blob)?;
            self.ovf_len.store(self.ovf.data_len(), Ordering::Release);
            let nlen = blob.len() as u64;
            let n_ovf = decode_ovf_blob(blob)?.len() as u32;
            (
                at,
                u32::try_from(nlen).map_err(|_| StoreError::Corrupt("txstat ovf len"))?,
                n_ovf,
            )
        };
        let slot_off = BLK_HEADER + (hfk - 1) * BLK_SLOT;
        let mut slot = [0u8; 16];
        slot[0..8].copy_from_slice(&off.to_le_bytes());
        slot[8..12].copy_from_slice(&len.to_le_bytes());
        slot[12..16].copy_from_slice(&n.to_le_bytes());
        self.blk.write_at_pwrite(slot_off, &slot)?;
        Ok(())
    }

    pub fn header_blob(&self, header_fk: Fk) -> Result<Vec<u8>, StoreError> {
        let hfk = header_fk.get().ok_or(StoreError::InvalidFk)?;
        let slot_off = BLK_HEADER + (hfk - 1) * BLK_SLOT;
        if slot_off + BLK_SLOT > self.blk.logical_len() {
            return Ok(Vec::new());
        }
        let mut slot = [0u8; 16];
        self.blk.read_at(slot_off, &mut slot)?;
        let off = u64::from_le_bytes(slot[0..8].try_into().unwrap());
        let len = u32::from_le_bytes(slot[8..12].try_into().unwrap()) as usize;
        if len == 0 {
            return Ok(Vec::new());
        }
        let remain = self.ovf.logical_len().saturating_sub(off);
        let len = checked_blob_len(len, remain)?;
        let mut buf = vec![0u8; len];
        self.ovf.read_at(off, &mut buf)?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    fn tiny(fee: u64, base: u32, wit: u32) -> TxStatRow {
        TxStatRow {
            fee_sat: fee,
            base,
            wit_extra: wit,
        }
    }

    #[test]
    fn txstat_blob_longer_than_the_file_is_corrupt() {
        let err = checked_blob_len(1 << 30, 32).expect_err("huge len");
        match err {
            StoreError::Corrupt(msg) => assert!(msg.contains("txstat"), "{msg}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(checked_blob_len(4, 32).unwrap(), 4);
    }

    #[test]
    fn create_empty_then_extend_zeros() {
        let dir = TempDir::labeled("txstat-extend").unwrap();
        let t = TxStat::create(&dir).unwrap();
        assert_eq!(t.count(), 0);
        t.extend_or_truncate_to(2).unwrap();
        assert_eq!(t.count(), 2);
        assert_eq!(t.get_cell(Fk(1)).unwrap(), [0u8; 8]);
        assert_eq!(t.get_cell(Fk(2)).unwrap(), [0u8; 8]);
        t.truncate_to_count(1).unwrap();
        assert_eq!(t.count(), 1);
        assert!(t.get_cell(Fk(2)).is_err());
    }

    #[test]
    fn uleb_typical_fits_in_cell() {
        let row = tiny(1000, 110, 112);
        let (cell, tail) = pack_cell(&row).unwrap();
        assert!(tail.is_none());
        assert_eq!(parse_cell(cell).unwrap(), CellParse::Complete(row));
        assert_eq!(row.size(), 222);
        assert_eq!(row.weight(), 4 * 110 + 112);
    }

    #[test]
    fn former_n_in_byte_no_longer_forces_a_tail() {
        let row = tiny(50_000, 200, 200_000);
        let (cell, tail) = pack_cell(&row).unwrap();
        assert!(tail.is_none(), "three fields of this row fit in 8 B");
        assert_eq!(parse_cell(cell).unwrap(), CellParse::Complete(row));
    }

    #[test]
    fn overflow_is_remaining_bytes_only() {
        let row = tiny(u64::from(u32::MAX), 4_000_000, 4_000_000);
        let stream = encode_stream(&row).unwrap();
        assert!(stream.len() > 8, "wide fee and sizes must miss 8 B");
        let (cell, tail) = pack_cell(&row).unwrap();
        let tail = tail.expect("tail");
        assert_eq!(tail.as_slice(), &stream[8..]);
        assert_eq!(parse_cell(cell).unwrap(), CellParse::NeedTail);
        assert_eq!(parse_with_tail(cell, &tail).unwrap(), row);
    }

    #[test]
    fn header_blob_roundtrip() {
        let dir = TempDir::labeled("txstat-ovf").unwrap();
        let t = TxStat::create(&dir).unwrap();
        let small = tiny(1000, 110, 0);
        let fat = tiny(u64::from(u32::MAX), 4_000_000, 4_000_000);
        t.append_batch(0, &[small, fat]).unwrap();
        t.write_block_rows(Fk(1), 1, &[small, fat]).unwrap();
        let blob = t.header_blob(Fk(1)).unwrap();
        assert!(!blob.is_empty());
        let got = t.get_range(1, 2, Some(&blob)).unwrap();
        assert_eq!(got[0], Some(small));
        assert_eq!(got[1], Some(fat));
        assert_eq!(t.get_row_merged(Fk(2), 1, &blob).unwrap(), Some(fat));
    }

    #[test]
    fn leftover_txfixed_body_unlinked_on_open() {
        let dir = TempDir::labeled("txstat-leftover").unwrap();
        std::fs::write(dir.join("txfixed.body"), b"junk").unwrap();
        let _t = TxStat::open(&dir).unwrap();
        assert!(!dir.join("txfixed.body").exists());
        assert!(dir.join("txstat.body").is_file());
    }
}
