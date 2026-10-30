//! One TDP template: budgeted mempool selection plus the coinbase split
//! (sv2-spec 07 §7.1–7.2).

use binary_sv2::{Seq0255, B0255, B064K, U256};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, ScriptBuf, Target, Transaction, TxOut};
use rbitcoin_consensus::{
    bip34_height_script, block_subsidy, witness_commitment_script, MAX_BLOCK_WEIGHT,
};
use rbitcoin_net::{ChainHub, SelectBudget};
use rbitcoin_primitives::Height;
use rbitcoin_query::{expected_next_bits, next_block_mintime};
use std::io;
use std::sync::{Arc, Mutex};
use template_distribution_sv2::{NewTemplate, SetNewPrevHash};
use tokio::sync::Semaphore;

/// Coinbase witness reserved value the template's witness commitment is
/// built with (BIP141).
pub const WITNESS_RESERVED_VALUE: [u8; 32] = [0u8; 32];

/// sv2-spec 07 §7.1: coinbase weight outside the client's additional outputs,
/// and the floor on the whole reserve.
#[doc(hidden)]
pub const COINBASE_BASE_WU: u64 = 1168;
#[doc(hidden)]
pub const MIN_COINBASE_RESERVE_WU: u64 = 2000;

#[derive(Clone)]
pub struct Template {
    pub version: u32,
    pub coinbase_prefix: Vec<u8>,
    pub value_remaining: u64,
    /// The witness commitment output, serialized with no count prefix.
    pub coinbase_outputs: Vec<u8>,
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
            merkle_path: Seq0255::new(self.merkle_path.iter().map(U256::from).collect())?,
        })
    }

    pub fn to_prev_hash(&self, template_id: u64) -> SetNewPrevHash<'_> {
        SetNewPrevHash {
            template_id,
            prev_hash: U256::from(&self.prev_hash),
            header_timestamp: self.header_timestamp,
            n_bits: self.n_bits,
            target: U256::from(&self.target),
        }
    }
}

/// Template on the stripped tip for one client's coinbase constraints. The
/// client's sigops replace the default reserve (Core `BlockAssembler`).
/// `Ok(None)` when that tip has not been recorded, or is no longer the
/// header at its height. Takes the mempool lock and reads the store:
/// blocking region only.
#[doc(hidden)]
pub fn build(
    chain: &ChainHub,
    max_additional_size: u32,
    max_additional_sigops: u16,
) -> io::Result<Option<Template>> {
    let Some(prev) = chain.mempool().and_then(|m| m.template_prev()) else {
        return Ok(None);
    };
    let Some(tip) = chain
        .query
        .height_of_hash(&prev)
        .map_err(|e| io::Error::other(format!("sv2: template tip: {e}")))?
    else {
        return Ok(None);
    };
    let header = chain
        .query
        .wire_header_at_height(tip)
        .map_err(|e| io::Error::other(format!("sv2: tip header: {e}")))?;
    if header.block_hash().to_byte_array() != prev {
        return Ok(None);
    }
    let height = tip.0 + 1;
    let testdummy = chain
        .query
        .testdummy_state(&chain.params, tip)
        .map_err(|e| io::Error::other(format!("sv2: versionbits: {e}")))?;
    let header_timestamp = next_block_mintime(&chain.query, &chain.params, tip)
        .map_err(|e| io::Error::other(format!("sv2: tip mintime: {e}")))?
        .max(chain.clock.now_secs() as u32);
    let bits = expected_next_bits(
        &chain.query,
        &chain.params,
        Height(height),
        header_timestamp,
    )
    .map_err(|e| io::Error::other(format!("sv2: next bits: {e}")))?;
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
    Ok(Some(Template {
        version: chain.gbt_block_version(testdummy) as u32,
        coinbase_prefix: bip34_height_script(height),
        value_remaining: (block_subsidy(height, &chain.params) as u64).saturating_add(fees),
        coinbase_outputs: serialize(&commitment),
        merkle_path: rbitcoin_store::merkle_branch(&leaves, 0),
        prev_hash: header.block_hash().to_byte_array(),
        header_timestamp,
        n_bits: bits.to_consensus(),
        target: Target::from_compact(bits).to_le_bytes(),
        txs: selected.into_iter().map(|(tx, _)| tx).collect(),
    }))
}

/// One template build. `prev_hash` is the stripped tip, or all zeros when
/// that tip has not been recorded. Sessions that share this key share one
/// build.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TemplateKey {
    pub prev_hash: [u8; 32],
    pub max_additional_size: u32,
    pub max_additional_sigops: u16,
    pub template_updates: u64,
}

/// One [`build`] at a time for this listener. The permit is taken on the
/// caller's task before `spawn_blocking`, so a second session waits without
/// a blocking-pool thread. The last `Ok(Some)` is kept and reused for that
/// same [`TemplateKey`]. A different key builds once the permit is free.
/// `Ok(None)` is not stored: IBD and an unmaintained pool retry.
pub struct TemplateFlight {
    one: Arc<Semaphore>,
    slot: Mutex<Option<(TemplateKey, Template)>>,
    /// The build task owns the flight permit. The handle stays here so the
    /// task is not detached at the call, and so a dropped session cannot
    /// abort a build that later sessions still share.
    inflight: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Default for TemplateFlight {
    fn default() -> Self {
        Self::new()
    }
}

impl TemplateFlight {
    pub fn new() -> Self {
        Self {
            one: Arc::new(Semaphore::new(1)),
            slot: Mutex::new(None),
            inflight: Mutex::new(None),
        }
    }

    fn cached(&self, key: &TemplateKey) -> Option<Template> {
        let g = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        g.as_ref().filter(|(k, _)| k == key).map(|(_, t)| t.clone())
    }

    /// Run `build` off the reactor when `key` is not already stored.
    /// The permit lives in a task that outlives this call, so a dropped
    /// session does not let a second build start, and the result is stored
    /// when the build finishes. A template whose `prev_hash` is not `key`'s
    /// is not stored.
    pub async fn get_or_build(
        self: &Arc<Self>,
        key: TemplateKey,
        build: impl FnOnce() -> io::Result<Option<Template>> + Send + 'static,
    ) -> io::Result<Option<Template>> {
        if let Some(hit) = self.cached(&key) {
            return Ok(Some(hit));
        }
        let permit = Arc::clone(&self.one)
            .acquire_owned()
            .await
            .expect("sv2 template flight");
        if let Some(hit) = self.cached(&key) {
            drop(permit);
            return Ok(Some(hit));
        }
        let flight = Arc::clone(self);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _permit = permit;
            let built = match tokio::task::spawn_blocking(build).await {
                Ok(built) => built,
                Err(e) => {
                    let _ = tx.send(Err(io::Error::other(e)));
                    return;
                }
            };
            let built = match built {
                Ok(t) => t,
                Err(e) => {
                    let _ = tx.send(Err(e));
                    return;
                }
            };
            if let Some(t) = built.clone() {
                if t.prev_hash == key.prev_hash {
                    *flight.slot.lock().unwrap_or_else(|e| e.into_inner()) = Some((key, t));
                }
            }
            let _ = tx.send(Ok(built));
        });
        *self.inflight.lock().unwrap_or_else(|e| e.into_inner()) = Some(task);
        rx.await
            .map_err(|_| io::Error::other("sv2 template flight dropped"))?
    }
}
