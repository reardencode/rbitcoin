use crate::error::ConsensusError;
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::Transaction;
use rbitcoin_primitives::Fk;
use rbitcoin_query::{Query, TxApply};
use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

pub fn header_to_record(prev_fk: Fk, header: &Header) -> HeaderRecord {
    HeaderRecord {
        prev_fk,
        version: header.version.to_consensus(),
        timestamp: header.time,
        bits: header.bits.to_consensus(),
        nonce: header.nonce,
        merkle_root: header.merkle_root.to_byte_array(),
        hash: header.block_hash().to_byte_array(),
    }
}

pub fn block_to_apply(
    query: &Query,
    header: &Header,
    txs: &[Transaction],
) -> Result<(HeaderRecord, Vec<TxApply>), ConsensusError> {
    let txids: Vec<[u8; 32]> = txs
        .iter()
        .map(|t| t.compute_txid().to_byte_array())
        .collect();
    block_to_apply_with_txids(query, header, txs, &txids)
}

/// Build archive records using **precomputed** txids (from structure validation).
///
/// Avoids a second `compute_txid` pass over every transaction — the hot path for
/// multi-worker IBD prep on large blocks.
pub fn block_to_apply_with_txids(
    query: &Query,
    header: &Header,
    txs: &[Transaction],
    txids: &[[u8; 32]],
) -> Result<(HeaderRecord, Vec<TxApply>), ConsensusError> {
    if txs.len() != txids.len() {
        return Err(ConsensusError::BadBlock("txid count mismatch"));
    }
    let prev_fk = if header.prev_blockhash.to_byte_array() == [0u8; 32] {
        Fk::NULL
    } else {
        query
            .get_header_by_hash(header.prev_blockhash.as_byte_array())?
            .map(|(fk, _)| fk)
            .ok_or(ConsensusError::BadPrev)?
    };
    block_to_apply_with_txids_prev(prev_fk, header, txs, txids)
}

/// Like [`block_to_apply_with_txids`] but **no store access** — caller supplies
/// `prev_fk` (use [`Fk::NULL`] on the IBD path where the header row already exists).
pub fn block_to_apply_with_txids_prev(
    prev_fk: Fk,
    header: &Header,
    txs: &[Transaction],
    txids: &[[u8; 32]],
) -> Result<(HeaderRecord, Vec<TxApply>), ConsensusError> {
    if txs.len() != txids.len() {
        return Err(ConsensusError::BadBlock("txid count mismatch"));
    }
    let header_rec = header_to_record(prev_fk, header);
    let mut out = Vec::with_capacity(txs.len());
    for (tx, txid) in txs.iter().zip(txids.iter()) {
        out.push(tx_to_apply(tx, *txid)?);
    }
    Ok((header_rec, out))
}

fn tx_to_apply(tx: &Transaction, txid: [u8; 32]) -> Result<TxApply, ConsensusError> {
    let inputs: Vec<InputRecord> = tx
        .input
        .iter()
        .map(|inp| {
            let is_cb = inp.previous_output.is_null()
                || (inp.previous_output.txid.to_byte_array() == [0u8; 32]
                    && inp.previous_output.vout == u32::MAX);
            InputRecord {
                prev_txid: inp.previous_output.txid.to_byte_array(),
                // Archive resolve fills create_fk before pack; coinbase stays NULL.
                create_fk: Fk::NULL,
                prev_index: if is_cb {
                    u32::MAX
                } else {
                    inp.previous_output.vout
                },
                sequence: inp.sequence.to_consensus_u32(),
                script_sig: inp.script_sig.to_bytes(),
                witness: inp.witness.to_vec(),
            }
        })
        .collect();

    let outputs: Vec<OutputRecord> = tx
        .output
        .iter()
        .map(|o| OutputRecord::unspent(o.value.to_sat() as i64, o.script_pubkey.to_bytes()))
        .collect();

    Ok(TxApply {
        tx: TxRecord {
            txid,
            version: tx.version.0,
            locktime: tx.lock_time.to_consensus_u32(),
            input_start_fk: Fk::NULL,
            input_count: inputs.len() as u32,
            output_start_fk: Fk::NULL,
            output_count: outputs.len() as u32,
        },
        inputs,
        outputs,
    })
}

/// Class A ins from wire + stamped spend edges (write-time encode).
pub(crate) fn input_records_from_wire(
    tx: &Transaction,
    spend_fk: Fk,
    edges: &[rbitcoin_query::SpendEdge],
) -> Result<Vec<InputRecord>, ConsensusError> {
    if tx.input.len() != edges.len() {
        return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
            "invariant: write encode spends/tx input mismatch",
        )));
    }
    let mut out = Vec::with_capacity(tx.input.len());
    for (inp, e) in tx.input.iter().zip(edges.iter()) {
        if e.spend_fk != spend_fk {
            return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                "invariant: write encode spend_fk mismatch",
            )));
        }
        let is_cb = inp.previous_output.is_null()
            || (inp.previous_output.txid.to_byte_array() == [0u8; 32]
                && inp.previous_output.vout == u32::MAX);
        if is_cb {
            out.push(InputRecord::coinbase(
                inp.sequence.to_consensus_u32(),
                inp.script_sig.to_bytes(),
                inp.witness.to_vec(),
            ));
            continue;
        }
        if e.create_fk.is_null() {
            return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                "invariant: write encode missing create_fk",
            )));
        }
        if e.prev_txid != inp.previous_output.txid.to_byte_array()
            || e.vout != inp.previous_output.vout
        {
            return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                "invariant: write encode edge/wire prevout mismatch",
            )));
        }
        out.push(InputRecord {
            prev_txid: inp.previous_output.txid.to_byte_array(),
            create_fk: e.create_fk,
            prev_index: inp.previous_output.vout,
            sequence: inp.sequence.to_consensus_u32(),
            script_sig: inp.script_sig.to_bytes(),
            witness: inp.witness.to_vec(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

    #[test]
    fn apply_with_precomputed_txid_matches_fresh_hash() {
        let tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x01]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let want = tx.compute_txid().to_byte_array();
        let apply = tx_to_apply(&tx, want).unwrap();
        assert_eq!(apply.tx.txid, want);
        assert_eq!(apply.inputs.len(), 1);
        assert_eq!(apply.outputs[0].value, 50_0000_0000);
        let edges = [rbitcoin_query::SpendEdge {
            prev_txid: [0u8; 32],
            vout: u32::MAX,
            spend_fk: Fk(9),
            create_fk: Fk::NULL,
        }];
        let ins = input_records_from_wire(&tx, Fk(9), &edges).unwrap();
        assert_eq!(ins, apply.inputs);
    }

    #[test]
    fn txid_count_mismatch_and_prev_null_genesis() {
        use bitcoin::block::{Header, Version};
        use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};

        let tx = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x00, 0x01]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let header = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        let txid = tx.compute_txid().to_byte_array();
        // Mismatch paths.
        assert!(matches!(
            block_to_apply_with_txids_prev(Fk::NULL, &header, &[tx.clone()], &[]),
            Err(ConsensusError::BadBlock(_))
        ));
        assert!(matches!(
            block_to_apply_with_txids_prev(Fk::NULL, &header, &[], &[[0u8; 32]]),
            Err(ConsensusError::BadBlock(_))
        ));
        let (rec, apps) =
            block_to_apply_with_txids_prev(Fk::NULL, &header, &[tx], &[txid]).unwrap();
        assert!(rec.prev_fk.is_null());
        assert_eq!(apps.len(), 1);
        // Coinbase-like max vout on null prev with MAX index.
        let non_cb = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([1; 32]),
                    vout: 3,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let apply = tx_to_apply(&non_cb, non_cb.compute_txid().to_byte_array()).unwrap();
        assert_eq!(apply.inputs[0].prev_index, 3);
    }

    /// Write encode must bind each stamped spend edge to the wire prevout it
    /// claims to spend — a stale/mismatched edge is Corrupt, not encoded.
    #[test]
    fn input_encode_rejects_edge_wire_prevout_mismatch() {
        let tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([1; 32]),
                    vout: 3,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let edge = |prev_txid: [u8; 32], vout: u32| rbitcoin_query::SpendEdge {
            prev_txid,
            vout,
            spend_fk: Fk(9),
            create_fk: Fk(5),
        };
        let ok = input_records_from_wire(&tx, Fk(9), &[edge([1u8; 32], 3)]).unwrap();
        assert_eq!(ok[0].prev_txid, [1u8; 32]);
        assert_eq!(ok[0].prev_index, 3);
        for bad in [edge([2u8; 32], 3), edge([1u8; 32], 4)] {
            let err = input_records_from_wire(&tx, Fk(9), &[bad])
                .expect_err("mismatched edge must not encode");
            assert!(
                format!("{err}").contains("edge/wire prevout"),
                "unexpected error: {err}"
            );
        }
    }
}
