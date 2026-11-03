//! Bitcoin Core `mempool.dat` bytes (`src/node/mempool_persist.cpp`
//! `DumpMempool` / `LoadMempool`).
//!
//! | Field | Bytes |
//! |-------|-------|
//! | version | `u64` LE: 1 (no key) or 2 |
//! | key (version 2) | compact size 8, then the 8-byte XOR key |
//! | count | `u64` LE |
//! | per tx | witness serialization, `i64` entry time (s), `i64` fee delta |
//! | deltas | compact-size map of txid → `i64` for txids not listed above |
//! | unbroadcast | compact-size set of txids |
//!
//! In version 2 every byte after the key is XORed with `key[offset % 8]`,
//! where `offset` counts from the start of the file (Core `AutoFile`
//! position). This node keeps its own pool in `{datadir}/mempool/`; this
//! format only backs `savemempool` / `importmempool`.

use bitcoin::consensus::encode;
use bitcoin::hashes::Hash;
use bitcoin::{Transaction, Txid};
use std::collections::{BTreeMap, BTreeSet};

/// Core `MEMPOOL_DUMP_VERSION_NO_XOR_KEY`.
pub const VERSION_NO_XOR_KEY: u64 = 1;
/// Core `MEMPOOL_DUMP_VERSION`.
pub const VERSION_XOR_KEY: u64 = 2;
const KEY_SIZE: usize = 8;

/// One transaction entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreDatTx {
    pub tx: Transaction,
    /// Entry time, unix seconds.
    pub time: i64,
    /// `prioritisetransaction` delta (sat).
    pub fee_delta: i64,
}

/// A decoded `mempool.dat`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoreMempoolDat {
    /// Parents before children, as Core writes them.
    pub txs: Vec<CoreDatTx>,
    /// Deltas of txids that are not in [`Self::txs`].
    pub deltas: BTreeMap<Txid, i64>,
    pub unbroadcast: BTreeSet<Txid>,
}

impl CoreMempoolDat {
    /// Version 2 obfuscated with `key`, or version 1 for `None`.
    pub fn encode(&self, key: Option<[u8; KEY_SIZE]>) -> Vec<u8> {
        let version = if key.is_some() {
            VERSION_XOR_KEY
        } else {
            VERSION_NO_XOR_KEY
        };
        let mut out = version.to_le_bytes().to_vec();
        if let Some(k) = key {
            push_compact_size(&mut out, KEY_SIZE as u64);
            out.extend_from_slice(&k);
        }
        let body = out.len();
        out.extend_from_slice(&(self.txs.len() as u64).to_le_bytes());
        for e in &self.txs {
            out.extend_from_slice(&encode::serialize(&e.tx));
            out.extend_from_slice(&e.time.to_le_bytes());
            out.extend_from_slice(&e.fee_delta.to_le_bytes());
        }
        push_compact_size(&mut out, self.deltas.len() as u64);
        for (txid, delta) in &self.deltas {
            out.extend_from_slice(&txid.to_byte_array());
            out.extend_from_slice(&delta.to_le_bytes());
        }
        push_compact_size(&mut out, self.unbroadcast.len() as u64);
        for txid in &self.unbroadcast {
            out.extend_from_slice(&txid.to_byte_array());
        }
        if let Some(k) = key {
            xor_from(&mut out, body, &k);
        }
        out
    }

    /// Parse a version 1 or 2 file. Bytes after the unbroadcast set are
    /// ignored, as in Core.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut head = Reader { buf: bytes, pos: 0 };
        let key = match head.u64()? {
            VERSION_NO_XOR_KEY => None,
            VERSION_XOR_KEY => {
                if head.compact_size()? != KEY_SIZE as u64 {
                    return Err(format!(
                        "Obfuscation key size should be exactly {KEY_SIZE} bytes long"
                    ));
                }
                Some(head.array::<KEY_SIZE>()?)
            }
            other => return Err(format!("unknown mempool.dat version {other}")),
        };
        let mut plain = bytes.to_vec();
        if let Some(k) = key {
            xor_from(&mut plain, head.pos, &k);
        }
        let mut r = Reader {
            buf: &plain,
            pos: head.pos,
        };
        let count = r.u64()?;
        let mut txs = Vec::new();
        for _ in 0..count {
            let tx = r.tx()?;
            let time = r.i64()?;
            let fee_delta = r.i64()?;
            txs.push(CoreDatTx {
                tx,
                time,
                fee_delta,
            });
        }
        let mut deltas = BTreeMap::new();
        for _ in 0..r.compact_size()? {
            let txid = r.txid()?;
            deltas.insert(txid, r.i64()?);
        }
        let mut unbroadcast = BTreeSet::new();
        for _ in 0..r.compact_size()? {
            unbroadcast.insert(r.txid()?);
        }
        Ok(Self {
            txs,
            deltas,
            unbroadcast,
        })
    }
}

fn xor_from(buf: &mut [u8], start: usize, key: &[u8; KEY_SIZE]) {
    for (offset, b) in buf.iter_mut().enumerate().skip(start) {
        *b ^= key[offset % KEY_SIZE];
    }
}

fn push_compact_size(out: &mut Vec<u8>, n: u64) {
    out.extend(encode::serialize(&encode::VarInt(n)));
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], String> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(|| "end of data".to_string())?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        self.take(N)?
            .try_into()
            .map_err(|_| "end of data".to_string())
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn i64(&mut self) -> Result<i64, String> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    fn txid(&mut self) -> Result<Txid, String> {
        Ok(Txid::from_byte_array(self.array()?))
    }

    /// Core `ReadCompactSize`: canonical encodings only.
    fn compact_size(&mut self) -> Result<u64, String> {
        let (n, used) = encode::deserialize_partial::<encode::VarInt>(&self.buf[self.pos..])
            .map_err(|e| format!("ReadCompactSize(): {e}"))?;
        self.pos += used;
        Ok(n.0)
    }

    fn tx(&mut self) -> Result<Transaction, String> {
        let (tx, used) = encode::deserialize_partial::<Transaction>(&self.buf[self.pos..])
            .map_err(|e| format!("transaction: {e}"))?;
        self.pos += used;
        Ok(tx)
    }
}
