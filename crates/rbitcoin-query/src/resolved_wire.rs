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
        }
    }
}

/// One mutex snapshot of unresolved heights: still-raw vs already promoted.
///
/// `raw` is **(height, n_inputs)** — no payload clone. Lookup packs/holds
/// from the stamped count; decode clones via
/// [`crate::Query::block_queue_raw_payload`] only for heights it emits.
#[derive(Clone, Debug, Default)]
pub struct BlockQueueWaveIntake {
    pub raw: Vec<(u32, u32)>,
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
        };
        assert_eq!(stamped.n_inputs, 9);
    }
}
