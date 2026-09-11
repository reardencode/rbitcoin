//! Regtest generate / `submitblock`: mine locally; `submitblock` uses the
//! same [`ChainHub::accept_received_block`] path as P2P `block` messages.

use bitcoin::{Block, BlockHash, ScriptBuf, Transaction};
use rbitcoin_net::ChainHub;
use rbitcoin_rpc::{submit_received_block, RpcRegtest, SubmitBlockOutcome};
use std::sync::Arc;

/// Node-side [`RpcRegtest`] wrapping the live P2P confirm path.
pub struct HubRegtest(pub Arc<ChainHub>);

impl RpcRegtest for HubRegtest {
    fn generate_to_script(
        &self,
        nblocks: u32,
        script_pubkey: ScriptBuf,
        extra_txs: Vec<Transaction>,
    ) -> Result<Vec<BlockHash>, String> {
        self.0
            .generate_to_script(nblocks, script_pubkey, extra_txs)
            .map_err(|e| e.to_string())
    }

    fn assemble_block_to_script(
        &self,
        script_pubkey: ScriptBuf,
        extra_txs: Vec<Transaction>,
    ) -> Result<Block, String> {
        self.0
            .assemble_block_to_script(script_pubkey, extra_txs)
            .map_err(|e| e.to_string())
    }

    fn submit_block(&self, block: Block) -> SubmitBlockOutcome {
        submit_received_block(&self.0, block)
    }

    fn set_mock_time(&self, timestamp: i64) -> Result<(), String> {
        self.0.clock.set_mock(timestamp);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_query::Query;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn hub_regtest_generate_one() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-node-gen-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        let hub = Arc::new(ChainHub::new(
            Query::open_or_create_tiny(dir.join("store")).unwrap(),
            ChainParams::regtest(),
            Milestone::NONE,
        ));
        let miner = HubRegtest(hub);
        let hashes = miner
            .generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        assert_eq!(hashes.len(), 1);
        assert_eq!(miner.0.tip_height(), Some(1));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
