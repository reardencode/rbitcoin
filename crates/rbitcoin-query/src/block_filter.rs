//! BIP158 basic filters. Additive files under the datadir. Class A is unchanged.
//!
//! `blockfilters/basic.headers` is one 32-byte header per height.
//! `blockfilters/basic.bodies` is `u32` length then filter bytes, same order.
//! The watermark is the last sealed height. A missing directory is "not built".

use bitcoin::bip158::{BlockFilter, Error as Bip158Error, FilterHeader};
use bitcoin::hashes::Hash;
use bitcoin::{Block, OutPoint, ScriptBuf};
use rbitcoin_primitives::Height;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::{Query, QueryError};

const HEADER_LEN: u64 = 32;

fn dir(store: &Path) -> PathBuf {
    store.join("blockfilters")
}

fn headers_path(store: &Path) -> PathBuf {
    dir(store).join("basic.headers")
}

fn bodies_path(store: &Path) -> PathBuf {
    dir(store).join("basic.bodies")
}

/// Last sealed basic-filter height, if any header is on disk.
pub fn basic_filter_hwm(store: &Path) -> Result<Option<u32>, QueryError> {
    let path = headers_path(store);
    if !path.exists() {
        return Ok(None);
    }
    let len = fs::metadata(&path)
        .map_err(|e| rbitcoin_store::StoreError::io(&path, e))?
        .len();
    if len == 0 {
        return Ok(None);
    }
    if len % HEADER_LEN != 0 {
        return Err(rbitcoin_store::StoreError::Corrupt(
            "invariant: basic filter headers are not a multiple of 32",
        ));
    }
    Ok(Some((len / HEADER_LEN - 1) as u32))
}

/// Drop headers and bodies above `keep_through`. `None` removes the files.
pub fn truncate_basic_filters(store: &Path, keep_through: Option<u32>) -> Result<(), QueryError> {
    let headers = headers_path(store);
    let bodies = bodies_path(store);
    let Some(keep) = keep_through else {
        if headers.exists() {
            fs::remove_file(&headers).map_err(|e| rbitcoin_store::StoreError::io(&headers, e))?;
        }
        if bodies.exists() {
            fs::remove_file(&bodies).map_err(|e| rbitcoin_store::StoreError::io(&bodies, e))?;
        }
        return Ok(());
    };
    let Some(hwm) = basic_filter_hwm(store)? else {
        return Ok(());
    };
    if hwm <= keep {
        return Ok(());
    }
    let keep_headers = u64::from(keep).saturating_add(1) * HEADER_LEN;
    let hf = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&headers)
        .map_err(|e| rbitcoin_store::StoreError::io(&headers, e))?;
    hf.set_len(keep_headers)
        .map_err(|e| rbitcoin_store::StoreError::io(&headers, e))?;
    let body_end = body_offset_at(&bodies, keep.saturating_add(1))?;
    let bf = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&bodies)
        .map_err(|e| rbitcoin_store::StoreError::io(&bodies, e))?;
    bf.set_len(body_end)
        .map_err(|e| rbitcoin_store::StoreError::io(&bodies, e))?;
    Ok(())
}

fn body_offset_at(path: &Path, height: u32) -> Result<u64, QueryError> {
    let mut f = File::open(path).map_err(|e| rbitcoin_store::StoreError::io(path, e))?;
    let mut off = 0u64;
    for _ in 0..height {
        let mut len_b = [0u8; 4];
        f.read_exact(&mut len_b)
            .map_err(|e| rbitcoin_store::StoreError::io(path, e))?;
        let n = u32::from_le_bytes(len_b) as u64;
        off = off.saturating_add(4 + n);
        f.seek(SeekFrom::Current(n as i64))
            .map_err(|e| rbitcoin_store::StoreError::io(path, e))?;
    }
    Ok(off)
}

/// Append one basic filter. Caller must pass `height == hwm + 1` (or 0).
pub fn append_basic_filter(
    store: &Path,
    height: u32,
    block: &Block,
    script_for_coin: impl Fn(&OutPoint) -> Result<ScriptBuf, Bip158Error>,
) -> Result<FilterHeader, QueryError> {
    let hwm = basic_filter_hwm(store)?;
    let expect = hwm.map(|h| h.saturating_add(1)).unwrap_or(0);
    if height != expect {
        return Err(rbitcoin_store::StoreError::Corrupt(
            "invariant: basic filter append is not the next height",
        ));
    }
    let prev = match hwm {
        None => FilterHeader::from_byte_array([0u8; 32]),
        Some(_) => read_header_at(store, height - 1)?,
    };
    let filter = BlockFilter::new_script_filter(block, script_for_coin)
        .map_err(|_| rbitcoin_store::StoreError::Corrupt("invariant: basic filter build failed"))?;
    let header = filter.filter_header(&prev);
    let d = dir(store);
    fs::create_dir_all(&d).map_err(|e| rbitcoin_store::StoreError::io(&d, e))?;
    let hp = headers_path(store);
    let mut hf = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&hp)
        .map_err(|e| rbitcoin_store::StoreError::io(&hp, e))?;
    hf.write_all(&header.to_byte_array())
        .map_err(|e| rbitcoin_store::StoreError::io(&hp, e))?;
    let bp = bodies_path(store);
    let mut bf = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&bp)
        .map_err(|e| rbitcoin_store::StoreError::io(&bp, e))?;
    let n = filter.content.len() as u32;
    bf.write_all(&n.to_le_bytes())
        .map_err(|e| rbitcoin_store::StoreError::io(&bp, e))?;
    bf.write_all(&filter.content)
        .map_err(|e| rbitcoin_store::StoreError::io(&bp, e))?;
    Ok(header)
}

/// Filter bytes and header at `height`. `None` when the watermark has not reached it.
pub fn read_basic_filter(
    store: &Path,
    height: u32,
) -> Result<Option<(Vec<u8>, FilterHeader)>, QueryError> {
    let Some(hwm) = basic_filter_hwm(store)? else {
        return Ok(None);
    };
    if height > hwm {
        return Ok(None);
    }
    let header = read_header_at(store, height)?;
    let bodies = bodies_path(store);
    let off = body_offset_at(&bodies, height)?;
    let mut f = File::open(&bodies).map_err(|e| rbitcoin_store::StoreError::io(&bodies, e))?;
    f.seek(SeekFrom::Start(off))
        .map_err(|e| rbitcoin_store::StoreError::io(&bodies, e))?;
    let mut len_b = [0u8; 4];
    f.read_exact(&mut len_b)
        .map_err(|e| rbitcoin_store::StoreError::io(&bodies, e))?;
    let n = u32::from_le_bytes(len_b) as usize;
    let mut body = vec![0u8; n];
    f.read_exact(&mut body)
        .map_err(|e| rbitcoin_store::StoreError::io(&bodies, e))?;
    Ok(Some((body, header)))
}

impl Query {
    pub fn block_filter_enabled(&self) -> bool {
        self.block_filter_enabled
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn set_block_filter_index(&self, enabled: bool) {
        self.block_filter_enabled
            .store(enabled, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn basic_filter_hwm(&self) -> Result<Option<u32>, QueryError> {
        basic_filter_hwm(self.store.path())
    }

    pub fn basic_filter_at(
        &self,
        height: u32,
    ) -> Result<Option<(Vec<u8>, FilterHeader)>, QueryError> {
        read_basic_filter(self.store.path(), height)
    }

    /// Seal missing heights `(hwm, tip]`. No-op when the index flag is off.
    ///
    /// The post-IBD materialize step. After it, confirm seals each new height.
    pub fn backfill_block_filters(&self) -> Result<(), QueryError> {
        let Some(tip) = self.tip_height() else {
            return Ok(());
        };
        self.backfill_block_filters_through(tip.0)?;
        if self.block_filter_enabled() {
            self.block_filters_sealed
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }

    /// Whether confirm seals basic filters (index on and materialized).
    pub(crate) fn block_filters_follow_confirm(&self) -> bool {
        self.block_filter_enabled()
            && self
                .block_filters_sealed
                .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn backfill_block_filters_through(&self, through: u32) -> Result<(), QueryError> {
        if !self.block_filter_enabled() {
            return Ok(());
        }
        let start = self
            .basic_filter_hwm()?
            .map(|h| h.saturating_add(1))
            .unwrap_or(0);
        if start > through {
            return Ok(());
        }
        let t0 = std::time::Instant::now();
        for h in start..=through {
            let block = self.reconstruct_block_at_height(Height(h))?;
            let store = self.store.path();
            append_basic_filter(store, h, &block, |op| self.script_for_filter_coin(op))?;
        }
        rbitcoin_log::debug!(
            "ibd: perf blockfilter backfill {start}..={through} us={}",
            t0.elapsed().as_micros()
        );
        Ok(())
    }

    pub fn truncate_basic_filters_to_tip(&self) -> Result<(), QueryError> {
        truncate_basic_filters(self.store.path(), self.tip_height().map(|h| h.0))
    }

    fn script_for_filter_coin(&self, op: &OutPoint) -> Result<ScriptBuf, Bip158Error> {
        let txid = *op.txid.as_byte_array();
        let Some((fk, _)) = self
            .get_tx_by_txid(&txid)
            .map_err(|_| Bip158Error::UtxoMissing(*op))?
        else {
            return Err(Bip158Error::UtxoMissing(*op));
        };
        let out = self
            .tx_output_at_fk(fk, op.vout)
            .map_err(|_| Bip158Error::UtxoMissing(*op))?;
        Ok(ScriptBuf::from_bytes(out.script))
    }
}

fn read_header_at(store: &Path, height: u32) -> Result<FilterHeader, QueryError> {
    let path = headers_path(store);
    let mut f = File::open(&path).map_err(|e| rbitcoin_store::StoreError::io(&path, e))?;
    f.seek(SeekFrom::Start(u64::from(height) * HEADER_LEN))
        .map_err(|e| rbitcoin_store::StoreError::io(&path, e))?;
    let mut buf = [0u8; 32];
    f.read_exact(&mut buf)
        .map_err(|e| rbitcoin_store::StoreError::io(&path, e))?;
    Ok(FilterHeader::from_byte_array(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::Header;
    use bitcoin::block::Version;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::BlockHash;
    use bitcoin::{
        Amount, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode,
        TxOut, Witness,
    };

    fn one_output_block() -> Block {
        let tx = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        Block {
            header: Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
                merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
                time: 0,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            },
            txdata: vec![tx],
        }
    }

    #[test]
    fn basic_filter_appends_and_truncates() {
        let dir = crate::testutil::TempDir::labeled("bf").unwrap();
        let block = one_output_block();
        let h0 = append_basic_filter(dir.path(), 0, &block, |_| {
            Err(Bip158Error::UtxoMissing(OutPoint::null()))
        })
        .unwrap();
        assert_eq!(basic_filter_hwm(dir.path()).unwrap(), Some(0));
        let (body, header) = read_basic_filter(dir.path(), 0).unwrap().unwrap();
        assert_eq!(header, h0);
        assert!(!body.is_empty());
        let again = BlockFilter::new_script_filter(&block, |_| {
            Err::<ScriptBuf, _>(Bip158Error::UtxoMissing(OutPoint::null()))
        })
        .unwrap();
        assert_eq!(body, again.content);
        truncate_basic_filters(dir.path(), None).unwrap();
        assert_eq!(basic_filter_hwm(dir.path()).unwrap(), None);
    }

    #[test]
    fn basic_filter_resume_seals_only_the_next_height() {
        let dir = crate::testutil::TempDir::labeled("bf-resume").unwrap();
        let block = one_output_block();
        append_basic_filter(dir.path(), 0, &block, |_| {
            Err(Bip158Error::UtxoMissing(OutPoint::null()))
        })
        .unwrap();
        let sealed = read_basic_filter(dir.path(), 0).unwrap().unwrap();
        let err = append_basic_filter(dir.path(), 0, &block, |_| {
            Err(Bip158Error::UtxoMissing(OutPoint::null()))
        });
        assert!(err.is_err(), "a sealed height is not written again");
        append_basic_filter(dir.path(), 1, &block, |_| {
            Err(Bip158Error::UtxoMissing(OutPoint::null()))
        })
        .unwrap();
        assert_eq!(basic_filter_hwm(dir.path()).unwrap(), Some(1));
        truncate_basic_filters(dir.path(), Some(0)).unwrap();
        assert_eq!(basic_filter_hwm(dir.path()).unwrap(), Some(0));
        assert!(read_basic_filter(dir.path(), 1).unwrap().is_none());
        assert_eq!(
            read_basic_filter(dir.path(), 0).unwrap().unwrap().0,
            sealed.0
        );
    }
}
