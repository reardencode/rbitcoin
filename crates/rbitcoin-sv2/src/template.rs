//! One TDP template: budgeted mempool selection plus the coinbase split
//! (sv2-spec 07 §7.1–7.2).

use binary_sv2::{Seq0255, B0255, B064K, U256};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, CompactTarget, ScriptBuf, Target, Transaction, TxOut};
use rbitcoin_consensus::{
    bip34_height_script, block_subsidy, expected_next_bits, median_time_past,
    witness_commitment_script, MAX_BLOCK_WEIGHT,
};
use rbitcoin_net::{ChainHub, SelectBudget};
use rbitcoin_primitives::Height;
use std::io;
use std::sync::Arc;
use template_distribution_sv2::{NewTemplate, SetNewPrevHash};

/// Coinbase witness reserved value the template's witness commitment is
/// built with (BIP141).
pub(crate) const WITNESS_RESERVED_VALUE: [u8; 32] = [0u8; 32];

/// sv2-spec 07 §7.1: coinbase weight outside the client's additional outputs,
/// and the floor on the whole reserve.
const COINBASE_BASE_WU: u64 = 1168;
const MIN_COINBASE_RESERVE_WU: u64 = 2000;

/// A `NewTemplate`: the coinbase split the client completes, over a [`Job`].
pub(crate) struct Template {
    pub version: u32,
    pub coinbase_prefix: Vec<u8>,
    pub value_remaining: u64,
    /// The witness commitment output, serialized with no count prefix.
    pub coinbase_outputs: Vec<u8>,
    pub job: Job,
}

/// What a session retains under a template id, for a built template or a
/// validated custom job: the header fields a `SubmitSolution` is assembled
/// with and the txs `RequestTransactionData` returns.
pub(crate) struct Job {
    pub merkle_path: Vec<[u8; 32]>,
    pub prev_hash: [u8; 32],
    pub header_timestamp: u32,
    pub n_bits: u32,
    /// `n_bits` expanded, little-endian (no weak-block target).
    pub target: [u8; 32],
    /// Non-coinbase txs in block order: the mempool's own bodies, kept alive
    /// past eviction.
    pub txs: Vec<Arc<Transaction>>,
}

impl Template {
    /// Coinbase fields not carried by the record are fixed: version 2, one
    /// final input, zero locktime.
    pub fn to_message(
        &self,
        template_id: u64,
        future_template: bool,
    ) -> Result<NewTemplate<'_>, binary_sv2::Error> {
        Ok(NewTemplate {
            template_id,
            future_template,
            version: self.version,
            coinbase_tx_version: 2,
            coinbase_prefix: B0255::try_from(&self.coinbase_prefix[..])?,
            coinbase_tx_input_sequence: u32::MAX,
            coinbase_tx_value_remaining: self.value_remaining,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_outputs: B064K::try_from(&self.coinbase_outputs[..])?,
            coinbase_tx_locktime: 0,
            merkle_path: Seq0255::new(self.job.merkle_path.iter().map(U256::from).collect())?,
        })
    }

    pub fn to_prev_hash(&self, template_id: u64) -> SetNewPrevHash<'_> {
        SetNewPrevHash {
            template_id,
            prev_hash: U256::from(&self.job.prev_hash),
            header_timestamp: self.job.header_timestamp,
            n_bits: self.job.n_bits,
            target: U256::from(&self.job.target),
        }
    }
}

/// Header fields the tip fixes for the next block. Reads the store:
/// blocking region only.
pub(crate) struct NextHeader {
    pub height: u32,
    pub prev_hash: [u8; 32],
    /// MTP + 1, or the node clock when later.
    pub time: u32,
    pub bits: CompactTarget,
}

impl NextHeader {
    pub fn job(&self, merkle_path: Vec<[u8; 32]>, txs: Vec<Arc<Transaction>>) -> Job {
        Job {
            merkle_path,
            prev_hash: self.prev_hash,
            header_timestamp: self.time,
            n_bits: self.bits.to_consensus(),
            target: Target::from_compact(self.bits).to_le_bytes(),
            txs,
        }
    }
}

pub(crate) fn next_header(chain: &ChainHub) -> io::Result<NextHeader> {
    let tip = chain
        .query
        .tip_height()
        .ok_or_else(|| io::Error::other("sv2: no tip"))?;
    let header = chain
        .query
        .wire_header_at_height(tip)
        .map_err(|e| io::Error::other(format!("sv2: tip header: {e}")))?;
    let mtp = median_time_past(&chain.query, tip)
        .map_err(|e| io::Error::other(format!("sv2: tip MTP: {e}")))?;
    let height = tip.0 + 1;
    let time = mtp.saturating_add(1).max(chain.clock.now_secs() as u32);
    let bits = expected_next_bits(&chain.query, &chain.params, Height(height), time)
        .map_err(|e| io::Error::other(format!("sv2: next bits: {e}")))?;
    Ok(NextHeader {
        height,
        prev_hash: header.block_hash().to_byte_array(),
        time,
        bits,
    })
}

/// Template on the current tip for one client's coinbase constraints. The
/// client's sigops replace the default reserve (Core `BlockAssembler`).
/// Takes the mempool lock and reads the store: blocking region only.
pub(crate) fn build(
    chain: &ChainHub,
    max_additional_size: u32,
    max_additional_sigops: u16,
) -> io::Result<Template> {
    let next = next_header(chain)?;
    let height = next.height;
    let reserve =
        (COINBASE_BASE_WU + 4 * u64::from(max_additional_size)).max(MIN_COINBASE_RESERVE_WU);
    let budget = SelectBudget {
        max_weight_wu: MAX_BLOCK_WEIGHT.saturating_sub(reserve),
        reserved_sigops: u64::from(max_additional_sigops),
        min_sat_kvb: chain.block_min_tx_fee_sat_kvb(),
    };
    let selected = chain
        .mempool()
        .map(|m| m.select_block_template(budget))
        .unwrap_or_default();
    let fees: u64 = selected.iter().map(|(_, s)| s.fee_sat).sum();
    let commitment = TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(witness_commitment_script(
            selected
                .iter()
                .map(|(tx, _)| tx.compute_wtxid().to_byte_array()),
            &WITNESS_RESERVED_VALUE,
        )),
    };
    let mut leaves = vec![[0u8; 32]];
    leaves.extend(selected.iter().map(|(_, s)| s.txid.to_byte_array()));
    Ok(Template {
        version: chain.gbt_block_version() as u32,
        coinbase_prefix: bip34_height_script(height),
        value_remaining: (block_subsidy(height, &chain.params) as u64).saturating_add(fees),
        coinbase_outputs: serialize(&commitment),
        job: next.job(
            rbitcoin_store::merkle_branch(&leaves, 0),
            selected.into_iter().map(|(tx, _)| tx).collect(),
        ),
    })
}
