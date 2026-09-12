//! Lookup-promoted body-queue wire (decoded `Block` + [`TxPrecompute`]).

use crate::TxPrecompute;
use bitcoin::Block;
use std::sync::Arc;

/// Decoded body held after lookup drops the raw frame.
#[derive(Clone, Debug)]
pub struct ResolvedWire {
    pub block: Arc<Block>,
    pub pres: Arc<[TxPrecompute]>,
    /// Σ `tx.input.len()` (enqueue CompactSize or decode). Load-split uses this.
    pub n_inputs: u32,
    /// Class A header row from BQ enqueue. Load-split kinds via `has_body(fk)`.
    pub header_fk: u64,
    /// External `(prev_txid, vout)` from the BQ input walk (no coinbase / same-wave creates).
    pub spend_keys: Arc<[([u8; 32], u32)]>,
}

impl ResolvedWire {
    /// Stamp `n_inputs` from the decoded block (tests / callers without enqueue meta).
    pub fn new(block: Arc<Block>, pres: Arc<[TxPrecompute]>) -> Self {
        let n_inputs = block
            .txdata
            .iter()
            .map(|tx| tx.input.len() as u32)
            .fold(0u32, u32::saturating_add);
        Self {
            block,
            pres,
            n_inputs,
            header_fk: 0,
            spend_keys: Arc::from([]),
        }
    }
}

/// One mutex snapshot of unresolved heights: still-raw vs already promoted.
///
/// `raw` is **(height, n_inputs, header_fk)** — no payload clone. Lookup
/// packs/holds from the stamped count; decode clones via
/// [`crate::Query::block_queue_raw_payload`] only for heights it emits.
#[derive(Clone, Debug, Default)]
pub struct BlockQueueWaveIntake {
    pub raw: Vec<(u32, u32, u64)>,
    pub resolved: Vec<(u32, ResolvedWire)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_wire_stamps_n_inputs() {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let n = genesis
            .txdata
            .iter()
            .map(|tx| tx.input.len() as u32)
            .fold(0u32, u32::saturating_add);
        let pres: Arc<[TxPrecompute]> = genesis
            .txdata
            .iter()
            .map(TxPrecompute::from_tx)
            .collect::<Vec<_>>()
            .into();
        let wire = ResolvedWire::new(Arc::new(genesis), pres);
        assert_eq!(wire.n_inputs, n);
        assert_eq!(n, 1);
        let stamped = ResolvedWire {
            block: Arc::clone(&wire.block),
            pres: Arc::clone(&wire.pres),
            n_inputs: 9,
            header_fk: 7,
            spend_keys: Arc::from([([0x11u8; 32], 3)]),
        };
        assert_eq!(stamped.n_inputs, 9);
        assert_eq!(stamped.header_fk, 7);
        assert_eq!(wire.header_fk, 0);
        assert_eq!(stamped.spend_keys.as_ref(), &[([0x11u8; 32], 3)]);
    }
}
