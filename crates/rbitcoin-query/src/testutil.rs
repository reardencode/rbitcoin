//! Drop-cleaning Tiny [`Query`](crate::Query) for tests. Not an operator API.
//!
//! TxApply → dummy [`bitcoin::Block`] conversion lives here (Q-21), not in
//! production [`Query`] archive.

pub use rbitcoin_store::testutil::TempDir;

use crate::{Query, QueryError, TxApply};
use bitcoin::hashes::Hash;
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_store::HeaderRecord;

/// Tiny-head query in a drop-cleaning directory (not Mainnet GiB heads).
pub fn tiny_query() -> (TempDir, Query) {
    tiny_query_labeled("query")
}

pub fn tiny_query_labeled(label: &str) -> (TempDir, Query) {
    let dir = TempDir::labeled(label).expect("create temp dir");
    let q = Query::open_or_create_tiny(dir.path()).expect("open_or_create_tiny");
    (dir, q)
}

pub fn tx_apply_to_tx(ta: &TxApply) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: bitcoin::transaction::Version(ta.tx.version),
        lock_time: bitcoin::absolute::LockTime::from_consensus(ta.tx.locktime),
        input: ta
            .inputs
            .iter()
            .map(|inp| bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array(inp.prev_txid),
                    vout: inp.prev_index,
                },
                script_sig: bitcoin::script::ScriptBuf::from_bytes(inp.script_sig.clone()),
                sequence: bitcoin::Sequence::from_consensus(inp.sequence),
                witness: bitcoin::Witness::from_slice(&inp.witness),
            })
            .collect(),
        output: ta
            .outputs
            .iter()
            .map(|o| bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(o.value.max(0) as u64),
                script_pubkey: bitcoin::script::ScriptBuf::from_bytes(o.script.clone()),
            })
            .collect(),
    }
}

pub fn block_from_applies(txs: &[TxApply]) -> (bitcoin::Block, Vec<[u8; 32]>) {
    let txids: Vec<[u8; 32]> = txs.iter().map(|t| t.tx.txid).collect();
    let txdata: Vec<bitcoin::Transaction> = txs.iter().map(tx_apply_to_tx).collect();
    let block = bitcoin::Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: bitcoin::BlockHash::from_byte_array([0; 32]),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0; 32]),
            time: 1,
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata,
    };
    (block, txids)
}

/// Fixture Class A / connect. Converts TxApply once, then shipped
/// [`Query::archive_class_a_from_wire`].
pub trait FixtureChain {
    fn commit_class_a_only(&self, header: &HeaderRecord, txs: &[TxApply])
        -> Result<Fk, QueryError>;
    fn connect_block(
        &self,
        height: Height,
        header: &HeaderRecord,
        txs: &[TxApply],
    ) -> Result<Fk, QueryError>;
}

impl FixtureChain for Query {
    fn commit_class_a_only(
        &self,
        header: &HeaderRecord,
        txs: &[TxApply],
    ) -> Result<Fk, QueryError> {
        let fk = self.ensure_header(header)?;
        if self.store().header_txs.has_body(fk)? {
            return Ok(fk);
        }
        if txs.is_empty() {
            return Ok(fk);
        }
        let (block, txids) = block_from_applies(txs);
        self.archive_class_a_from_wire(&[(fk, &block, txids.as_slice())])?;
        Ok(fk)
    }

    fn connect_block(
        &self,
        height: Height,
        header: &HeaderRecord,
        txs: &[TxApply],
    ) -> Result<Fk, QueryError> {
        self.commit_class_a_only(header, txs)?;
        let fk = self.confirm_block(height, &header.hash)?;
        self.apply_sh_pending()?;
        Ok(fk)
    }
}
