//! Reconstruct wire blocks/txs and merkle proofs.

use super::*;
use crate::U64Map;
use std::time::Instant;

impl Query {
    /// Body for wire rebuild / RPC via `tx.idx`.
    fn load_body_for_wire(
        &self,
        fk: Fk,
    ) -> Result<(TxRecord, Vec<OutputRecord>, Vec<InputRecord>), QueryError> {
        self.load_body_from_store(fk)
    }

    fn load_body_from_store(
        &self,
        fk: Fk,
    ) -> Result<(TxRecord, Vec<OutputRecord>, Vec<InputRecord>), QueryError> {
        use crate::wave_fill_stats::{self as wf, add as wf_add, add_count as wf_count};
        let t0 = Instant::now();
        wf_count(&wf::BODY_STORE, 1);
        let (tx, inputs, outs) = self.store.get_tx_full(fk)?;
        wf_add(&wf::BODY_STORE_NS, t0.elapsed().as_nanos() as u64);
        Ok((tx, outs, inputs))
    }

    /// Create txids in block order from `txid.body` (no packed `txout` decode).
    pub fn block_txids(&self, height: Height) -> Result<Vec<[u8; 32]>, QueryError> {
        let header_fk = self
            .store
            .confirmed
            .get(height)?
            .ok_or(StoreError::NotFound)?;
        let (first, n) = self
            .store
            .header_txs
            .get_range(header_fk)?
            .ok_or(StoreError::Corrupt("confirmed header missing body list"))?;
        if n == 0 {
            return Ok(Vec::new());
        }
        let last = first.0.saturating_add(u64::from(n.saturating_sub(1)));
        let ids = self.store.txs.body_txid_range(first.0, last)?;
        if ids.len() != n as usize {
            return Err(StoreError::Corrupt("invariant: block txid.body length"));
        }
        Ok(ids)
    }

    /// One create identity at `index` in the block (`txid.body` only).
    pub fn block_txid_at(&self, height: Height, index: usize) -> Result<[u8; 32], QueryError> {
        let fks = self.block_tx_fks(height)?;
        let fk = *fks.get(index).ok_or(StoreError::NotFound)?;
        Ok(self.store.txs.body_txid(fk)?)
    }

    pub fn merkle_proof(&self, height: Height, txid: &[u8; 32]) -> Result<MerkleProof, QueryError> {
        use bitcoin::hashes::{sha256d, Hash as _};

        let txids = self.block_txids(height)?;
        let pos = txids
            .iter()
            .position(|t| t == txid)
            .ok_or(StoreError::NotFound)?;
        let mut branch = Vec::new();
        let mut idx = pos;
        let mut layer: Vec<[u8; 32]> = txids;
        while layer.len() > 1 {
            if layer.len() % 2 == 1 {
                layer.push(*layer.last().unwrap());
            }
            let sibling = if idx % 2 == 0 {
                layer[idx + 1]
            } else {
                layer[idx - 1]
            };
            branch.push(sibling);
            let mut next = Vec::with_capacity(layer.len() / 2);
            let mut i = 0;
            while i < layer.len() {
                let mut buf = [0u8; 64];
                buf[0..32].copy_from_slice(&layer[i]);
                buf[32..64].copy_from_slice(&layer[i + 1]);
                next.push(sha256d::Hash::hash(&buf).to_byte_array());
                i += 2;
            }
            layer = next;
            idx /= 2;
        }
        Ok(MerkleProof {
            block_height: height.0,
            pos,
            merkle: branch,
        })
    }

    pub fn block_tx_fks(&self, height: Height) -> Result<Vec<Fk>, QueryError> {
        let header_fk = self
            .store
            .confirmed
            .get(height)?
            .ok_or(StoreError::NotFound)?;
        self.store
            .header_txs
            .get_list(header_fk)?
            .ok_or(StoreError::Corrupt("confirmed header missing body list"))
    }

    fn contiguous_fk_run(fks: &[Fk]) -> Option<(u64, u64)> {
        let first = fks.first()?.get()?;
        if first == 0 {
            return None;
        }
        for (i, fk) in fks.iter().enumerate() {
            if fk.get() != Some(first + i as u64) {
                return None;
            }
        }
        Some((first, first + (fks.len() as u64).saturating_sub(1)))
    }

    /// Reconstruct a consensus `Transaction` from Class A rows (no stored raw).
    pub fn reconstruct_tx(&self, tx_fk: Fk) -> Result<Transaction, QueryError> {
        let (rec, stored_outputs, mut stored_inputs) = self.load_body_for_wire(tx_fk)?;
        let mut cache = U64Map::default();
        self.fill_input_prev_txids_cached(&mut stored_inputs, &mut cache)?;
        Ok(Self::transaction_from_class_a(
            rec,
            stored_outputs,
            stored_inputs,
        ))
    }

    fn transaction_from_class_a(
        rec: TxRecord,
        stored_outputs: Vec<OutputRecord>,
        stored_inputs: Vec<InputRecord>,
    ) -> Transaction {
        // Soft prev_txid may be zero after disk decode — fill from create body below
        // only when caller used fill_input_prev_txids first. Prefer non-zero soft.
        let mut input = Vec::with_capacity(stored_inputs.len());
        for inp in stored_inputs {
            let prev_txid = inp.prev_txid;
            input.push(TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array(prev_txid),
                    vout: inp.prev_index,
                },
                script_sig: ScriptBuf::from_bytes(inp.script_sig),
                sequence: Sequence::from_consensus(inp.sequence),
                witness: {
                    let refs: Vec<&[u8]> = inp.witness.iter().map(|w| w.as_slice()).collect();
                    Witness::from_slice(&refs)
                },
            });
        }
        let mut output = Vec::with_capacity(stored_outputs.len());
        for out in stored_outputs {
            output.push(TxOut {
                value: Amount::from_sat(out.value as u64),
                script_pubkey: ScriptBuf::from_bytes(out.script),
            });
        }
        Transaction {
            version: TxVersion(rec.version),
            lock_time: LockTime::from_consensus(rec.locktime),
            input,
            output,
        }
    }

    /// Resolve soft `prev_txid` from create_fk without re-reading every parent body.
    ///
    /// Schema v10 stamps create_fk and leaves soft prev_txid zero on disk. Prefer:
    /// 1. already-filled soft prev_txid
    /// 2. confirm parent cache (sparse pin / body)
    /// 3. store `body_txid` (deduped via `cache` across a block)
    pub(crate) fn fill_input_prev_txids_cached(
        &self,
        inputs: &mut [InputRecord],
        cache: &mut U64Map<[u8; 32]>,
    ) -> Result<(), QueryError> {
        for inp in inputs.iter_mut() {
            if inp.is_coinbase() {
                inp.prev_txid = [0u8; 32];
                continue;
            }
            if inp.prev_txid != [0u8; 32] {
                continue;
            }
            let Some(id) = inp.create_fk.get() else {
                return Err(StoreError::Corrupt(
                    "input missing create_fk for wire rebuild",
                ));
            };
            if let Some(&txid) = cache.get(&id) {
                inp.prev_txid = txid;
                continue;
            }
            let txid = self.store.txs.body_txid(Fk(id))?;
            if txid == [0u8; 32] {
                return Err(StoreError::Corrupt(
                    "wire rebuild: create identity still zero after txid.body",
                ));
            }
            cache.insert(id, txid);
            inp.prev_txid = txid;
        }
        Ok(())
    }

    /// Consensus-encoded wire bytes for a stored tx (Electrum / RPC).
    pub fn tx_wire_bytes(&self, tx_fk: Fk) -> Result<Vec<u8>, QueryError> {
        use bitcoin::consensus::Encodable;
        let tx = self.reconstruct_tx(tx_fk)?;
        let mut raw = Vec::new();
        tx.consensus_encode(&mut raw)
            .map_err(|_| StoreError::Corrupt("tx encode"))?;
        Ok(raw)
    }

    pub fn reconstruct_archived_block(&self, hash: &[u8; 32]) -> Result<Option<Block>, QueryError> {
        self.note_reconstruct_archived();
        let Some((header_fk, rec)) = self.get_header_by_hash(hash)? else {
            return Ok(None);
        };
        let Some(tx_fks) = self.store.header_txs.get_list(header_fk)? else {
            return Ok(None);
        };
        self.reconstruct_archived_block_from_parts(rec, tx_fks)
            .map(Some)
    }

    /// Wire rebuild when header row + tx fk list are already known.
    pub fn reconstruct_archived_block_from_parts(
        &self,
        rec: HeaderRecord,
        tx_fks: Vec<Fk>,
    ) -> Result<Block, QueryError> {
        self.reconstruct_archived_block_from_parts_cached(rec, tx_fks, None)
    }

    /// `prev_hash`: when set (load header plan), wire header needs no store IO.
    pub fn reconstruct_archived_block_from_parts_cached(
        &self,
        rec: HeaderRecord,
        tx_fks: Vec<Fk>,
        prev_hash: Option<[u8; 32]>,
    ) -> Result<Block, QueryError> {
        if tx_fks.is_empty() {
            return Err(StoreError::Corrupt("block has no transactions"));
        }
        let header = self.wire_header_from_record_prev(&rec, prev_hash)?;
        let mut txdata = Vec::with_capacity(tx_fks.len());
        let mut prev_txid_cache: U64Map<[u8; 32]> = U64Map::default();
        if let Some((first, last)) = Self::contiguous_fk_run(&tx_fks) {
            let rows = self.store.get_tx_full_span(first, last)?;
            if rows.len() != tx_fks.len() {
                return Err(StoreError::Corrupt("invariant: span reconstruct length"));
            }
            for (i, (rec_tx, mut stored_inputs, stored_outputs)) in rows.into_iter().enumerate() {
                if let Some(id) = tx_fks[i].get() {
                    prev_txid_cache.insert(id, rec_tx.txid);
                }
                self.fill_input_prev_txids_cached(&mut stored_inputs, &mut prev_txid_cache)?;
                txdata.push(Self::transaction_from_class_a(
                    rec_tx,
                    stored_outputs,
                    stored_inputs,
                ));
            }
        } else {
            for fk in tx_fks {
                let (rec_tx, stored_outputs, mut stored_inputs) = self.load_body_for_wire(fk)?;
                self.fill_input_prev_txids_cached(&mut stored_inputs, &mut prev_txid_cache)?;
                txdata.push(Self::transaction_from_class_a(
                    rec_tx,
                    stored_outputs,
                    stored_inputs,
                ));
            }
        }
        Ok(Block { header, txdata })
    }

    /// Reconstruct a full wire block at a confirmed height from the relational archive.
    pub fn reconstruct_block_at_height(&self, height: Height) -> Result<Block, QueryError> {
        let (_fk, rec) = self.header_at_height(height)?.ok_or(StoreError::NotFound)?;
        let tx_fks = self.block_tx_fks(height)?;
        let block = self.reconstruct_archived_block_from_parts_cached(rec.clone(), tx_fks, None)?;
        if block.block_hash().to_byte_array() != rec.hash {
            return Err(StoreError::Corrupt("reconstruct hash mismatch"));
        }
        Ok(block)
    }

    /// Reconstruct by block hash if the hash is on the best (confirmed) chain.
    pub fn reconstruct_block_by_hash(&self, hash: &[u8; 32]) -> Result<Option<Block>, QueryError> {
        match self.height_of_hash(hash)? {
            None => Ok(None),
            Some(h) => Ok(Some(self.reconstruct_block_at_height(h)?)),
        }
    }
}
