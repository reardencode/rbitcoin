//! Regtest generate / `submitblock`: mine locally; `submitblock` uses the
//! same [`ChainHub::accept_received_block`] path as P2P `block` messages.

use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, ScriptBuf, Transaction};
use rbitcoin_net::{AcceptOutcome, ChainHub};
use rbitcoin_rpc::{RpcRegtest, SubmitBlockOutcome};
use std::sync::Arc;

/// Structure / value rejects that Core surfaces before header-time on submit.
fn cheap_submit_tx_reject(query: &rbitcoin_query::Query, block: &Block) -> Option<String> {
    use bitcoin::{Amount, OutPoint, TxOut};
    if block.txdata.is_empty() {
        return Some("bad-blk-length".into());
    }
    let mut seen = std::collections::HashSet::new();
    let mut spent = std::collections::HashSet::new();
    let mut created: std::collections::HashMap<OutPoint, TxOut> = std::collections::HashMap::new();
    for (i, tx) in block.txdata.iter().enumerate() {
        if !seen.insert(tx.compute_txid()) {
            return Some("bad-txns-duplicate".into());
        }
        if i == 0 {
            if !tx.is_coinbase() {
                return Some("bad-cb-missing".into());
            }
            let tid = tx.compute_txid();
            for (v, o) in tx.output.iter().enumerate() {
                created.insert(
                    OutPoint {
                        txid: tid,
                        vout: v as u32,
                    },
                    o.clone(),
                );
            }
            continue;
        }
        let mut in_val = 0u64;
        for inp in &tx.input {
            let op = inp.previous_output;
            if !spent.insert(op) {
                return Some("bad-txns-inputs-missingorspent".into());
            }
            let txout = if let Some(o) = created.get(&op) {
                o.clone()
            } else {
                let tid = op.txid.to_byte_array();
                if query.is_outpoint_spent(&tid, op.vout).ok().unwrap_or(true) {
                    return Some("bad-txns-inputs-missingorspent".into());
                }
                let Some((fk, rec)) = query.get_tx_by_txid(&tid).ok().flatten() else {
                    return Some("bad-txns-inputs-missingorspent".into());
                };
                let Some(out) = query
                    .tx_output_at_fk(fk, op.vout)
                    .ok()
                    .or_else(|| query.tx_output(&rec, op.vout).ok())
                else {
                    return Some("bad-txns-inputs-missingorspent".into());
                };
                let value = if out.value < 0 {
                    Amount::ZERO
                } else {
                    Amount::from_sat(out.value as u64)
                };
                TxOut {
                    value,
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(out.script),
                }
            };
            in_val = in_val.saturating_add(txout.value.to_sat());
        }
        let out_val: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        if out_val > in_val {
            return Some("bad-txns-in-belowout".into());
        }
        let tid = tx.compute_txid();
        for (v, o) in tx.output.iter().enumerate() {
            created.insert(
                OutPoint {
                    txid: tid,
                    vout: v as u32,
                },
                o.clone(),
            );
        }
    }
    None
}

fn submit_reject_reason(e: &rbitcoin_net::NetError) -> String {
    if matches!(e, rbitcoin_net::NetError::UnknownParent) {
        return "prev-blk-not-found".into();
    }
    submit_reject_reason_str(&e.to_string())
}

fn submit_reject_reason_str(s: &str) -> String {
    let s = s.strip_prefix("consensus: ").unwrap_or(s);
    let s = s.strip_prefix("protocol: ").unwrap_or(s);
    if s.contains("unknown parent") || s.contains("BadPrev") || s.contains("unexpected previous") {
        return "prev-blk-not-found".into();
    }
    if s.contains("pow invalid") || s.contains("InvalidPow") || s.contains("high-hash") {
        return "high-hash".into();
    }
    for needle in [
        "bad-txns-nonfinal",
        "bad-txns-duplicate",
        "bad-txns-inputs-missingorspent",
        "bad-txns-in-belowout",
        "bad-cb-missing",
        "bad-blk-length",
        "bad-diffbits",
        "time-too-old",
        "time-too-new",
        "bad-txnmrklroot",
    ] {
        if s.contains(needle) {
            return needle.into();
        }
    }
    s.to_string()
}

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
        use bitcoin::Target;
        let hash = block.block_hash();
        if self.0.is_block_invalid(&hash) {
            return SubmitBlockOutcome::Rejected("duplicate-invalid".into());
        }
        let target = Target::from_compact(block.header.bits);
        if block.header.validate_pow(target).is_err() {
            return SubmitBlockOutcome::Rejected("high-hash".into());
        }
        let prev = block.header.prev_blockhash.to_byte_array();
        // Only "not found" when we have never seen the parent header. A known
        // side parent must still go through accept (hold + most-work branch).
        let known = self
            .0
            .query
            .get_header_by_hash(&prev)
            .ok()
            .flatten()
            .is_some()
            || self
                .0
                .held_body(&bitcoin::BlockHash::from_byte_array(prev))
                .is_some();
        if !known {
            return SubmitBlockOutcome::Rejected("prev-blk-not-found".into());
        }
        if let Some(reason) = cheap_submit_tx_reject(self.0.query.as_ref(), &block) {
            return SubmitBlockOutcome::Rejected(reason);
        }
        match self.0.accept_received_block(block.clone()) {
            Ok(AcceptOutcome::Accepted { .. }) => SubmitBlockOutcome::Accepted,
            Ok(AcceptOutcome::AlreadyHave) => SubmitBlockOutcome::Duplicate,
            Ok(AcceptOutcome::IgnoredWeaker) => SubmitBlockOutcome::IgnoredWeaker,
            Err(e) => {
                let reason = submit_reject_reason(&e);
                // Mutated merkle / missing parent stay retryable. Other
                // consensus rejects mark the hash so a second submit is
                // `duplicate-invalid` and children get `bad-prevblk`.
                if reason != "bad-txnmrklroot"
                    && reason != "high-hash"
                    && reason != "prev-blk-not-found"
                {
                    self.0.note_invalid_block(hash);
                    let _ = self.0.ensure_header(&block.header);
                }
                SubmitBlockOutcome::Rejected(reason)
            }
        }
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
