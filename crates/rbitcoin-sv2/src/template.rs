//! One TDP template: budgeted mempool selection plus the coinbase split
//! (sv2-spec 07 §7.1–7.2).

use binary_sv2::{Seq0255, B0255, B064K, U256};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, CompactTarget, ScriptBuf, Target, Transaction, TxOut};
use rbitcoin_consensus::{
    bip34_height_script, block_subsidy, witness_commitment_script, MAX_BLOCK_WEIGHT,
};
use rbitcoin_net::{ChainHub, SelectBudget};
use rbitcoin_primitives::Height;
use rbitcoin_query::{expected_next_bits, next_block_mintime};
use std::collections::HashMap;
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

/// A `NewTemplate`: the coinbase split the client completes, over a [`Job`].
#[derive(Clone)]
pub struct Template {
    pub version: u32,
    pub coinbase_prefix: Vec<u8>,
    pub value_remaining: u64,
    /// The witness commitment output, serialized with no count prefix.
    pub coinbase_outputs: Vec<u8>,
    /// `SetNewPrevHash.n_bits` and `target` (`n_bits` expanded,
    /// little-endian, no weak-block target) for this template's prev hash.
    pub n_bits: u32,
    pub target: [u8; 32],
    pub job: Job,
}

/// What a session retains under a template id, for a built template or a
/// validated custom job: the header fields a `SubmitSolution` is assembled
/// with and the txs `RequestTransactionData` returns.
#[doc(hidden)]
#[derive(Clone)]
pub struct Job {
    pub merkle_path: Vec<[u8; 32]>,
    pub prev_hash: [u8; 32],
    pub header_timestamp: u32,
    pub bits: Bits,
    /// Non-coinbase txs in block order: the mempool's own bodies, kept alive
    /// past eviction.
    pub txs: Vec<Arc<Transaction>>,
}

/// Where a `SubmitSolution` gets the `nBits` of the header it assembles. The
/// bits are inside the hash, so a header built with other bits than the
/// miner hashed misses its target or is a different block.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bits {
    /// A pushed template: the bits `SetNewPrevHash` sent for its prev hash,
    /// which the client hashed.
    Sent(u32),
    /// A validated custom job: the JDC hashed what its own TP sent, which
    /// this session never saw. Consensus fixes the bits of a child of the
    /// job's parent at the solution's time, so that is what is hashed.
    Consensus,
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
            n_bits: self.n_bits,
            target: U256::from(&self.target),
        }
    }
}

/// Header fields the tip fixes for the next block. Reads the store:
/// blocking region only.
#[derive(Clone, Copy)]
pub(crate) struct NextHeader {
    pub height: u32,
    pub prev_hash: [u8; 32],
    /// MTP + 1, or the node clock when later.
    pub time: u32,
    pub bits: CompactTarget,
}

impl NextHeader {
    pub fn job(&self, merkle_path: Vec<[u8; 32]>, txs: Vec<Arc<Transaction>>, bits: Bits) -> Job {
        Job {
            merkle_path,
            prev_hash: self.prev_hash,
            header_timestamp: self.time,
            bits,
            txs,
        }
    }
}

pub(crate) fn next_header(chain: &ChainHub) -> io::Result<NextHeader> {
    let tip = chain
        .query
        .tip_height()
        .ok_or_else(|| io::Error::other("sv2: no tip"))?;
    next_header_at(chain, tip)
}

fn next_header_at(chain: &ChainHub, tip: Height) -> io::Result<NextHeader> {
    let header = chain
        .query
        .wire_header_at_height(tip)
        .map_err(|e| io::Error::other(format!("sv2: tip header: {e}")))?;
    let height = tip.0 + 1;
    let time = next_block_mintime(&chain.query, &chain.params, tip)
        .map_err(|e| io::Error::other(format!("sv2: tip mintime: {e}")))?
        .max(chain.clock.now_secs() as u32);
    let bits = expected_next_bits(&chain.query, &chain.params, Height(height), time)
        .map_err(|e| io::Error::other(format!("sv2: next bits: {e}")))?;
    Ok(NextHeader {
        height,
        prev_hash: header.block_hash().to_byte_array(),
        time,
        bits,
    })
}

/// Template on the stripped tip for one client's coinbase constraints.
/// Returns `None` if that tip is missing or no longer at its height.
#[doc(hidden)]
pub fn build(
    chain: &ChainHub,
    max_additional_size: u32,
    max_additional_sigops: u16,
) -> io::Result<Option<Template>> {
    let Some(next) = prepare_next(chain)? else {
        return Ok(None);
    };
    build_next(chain, max_additional_size, max_additional_sigops, next)
}

/// The header fields a child of `prev` takes.
/// `Ok(None)` when `prev` is not the header at its height.
pub(crate) fn next_header_on(chain: &ChainHub, prev: [u8; 32]) -> io::Result<Option<NextHeader>> {
    let Some(tip) = chain
        .query
        .height_of_hash(&prev)
        .map_err(|e| io::Error::other(format!("sv2: template tip: {e}")))?
    else {
        return Ok(None);
    };
    let next = next_header_at(chain, tip)?;
    Ok((next.prev_hash == prev).then_some(next))
}

/// `template_prev` plus the bits and time a template on that tip would use.
/// `Ok(None)` when the pool has not recorded a stripped tip.
pub(crate) fn prepare_next(chain: &ChainHub) -> io::Result<Option<NextHeader>> {
    let Some(prev) = chain.mempool().and_then(|m| m.template_prev()) else {
        return Ok(None);
    };
    next_header_on(chain, prev)
}

/// [`build`] with the header fields already chosen. The flight key carries
/// those values, so a cached template matches the key that built it.
pub(crate) fn build_next(
    chain: &ChainHub,
    max_additional_size: u32,
    max_additional_sigops: u16,
    next: NextHeader,
) -> io::Result<Option<Template>> {
    let Some(tip) = chain
        .query
        .height_of_hash(&next.prev_hash)
        .map_err(|e| io::Error::other(format!("sv2: template tip: {e}")))?
    else {
        return Ok(None);
    };
    let header = chain
        .query
        .wire_header_at_height(tip)
        .map_err(|e| io::Error::other(format!("sv2: tip header: {e}")))?;
    if header.block_hash().to_byte_array() != next.prev_hash {
        return Ok(None);
    }
    let testdummy = chain
        .query
        .testdummy_state(&chain.params, tip)
        .map_err(|e| io::Error::other(format!("sv2: versionbits: {e}")))?;
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
    let n_bits = next.bits.to_consensus();
    Ok(Some(Template {
        version: chain.gbt_block_version(testdummy) as u32,
        coinbase_prefix: bip34_height_script(height),
        value_remaining: (block_subsidy(height, &chain.params) as u64).saturating_add(fees),
        coinbase_outputs: serialize(&commitment),
        n_bits,
        target: Target::from_compact(next.bits).to_le_bytes(),
        job: next.job(
            rbitcoin_store::merkle_branch(&leaves, 0),
            selected.into_iter().map(|(tx, _)| tx).collect(),
            Bits::Sent(n_bits),
        ),
    }))
}

/// One template build. Sessions that share this key share one build.
/// `n_bits` and `header_timestamp` are part of the key: on testnet a later
/// session must not reuse an earlier template's time or difficulty.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TemplateKey {
    pub prev_hash: [u8; 32],
    pub max_additional_size: u32,
    pub max_additional_sigops: u16,
    pub template_updates: u64,
    pub header_timestamp: u32,
    pub n_bits: u32,
}

/// Idle templates kept per listener. A live build is never evicted.
const FLIGHT_CAP: usize = 8;

struct FlightGate {
    one: Arc<Semaphore>,
    slot: Mutex<Option<Template>>,
}

/// One [`build`] at a time for each [`TemplateKey`]. A different coinbase
/// budget, bits, or time does not wait on the others and does not evict
/// their template. The permit is taken on the caller's task before
/// `rbtc-off-pool`. `Ok(None)` is not stored.
pub struct TemplateFlight {
    gates: Mutex<HashMap<TemplateKey, Arc<FlightGate>>>,
}

impl Default for TemplateFlight {
    fn default() -> Self {
        Self::new()
    }
}

fn template_matches(key: &TemplateKey, t: &Template) -> bool {
    t.job.prev_hash == key.prev_hash
        && t.job.header_timestamp == key.header_timestamp
        && t.n_bits == key.n_bits
}

impl TemplateFlight {
    pub fn new() -> Self {
        Self {
            gates: Mutex::new(HashMap::new()),
        }
    }

    fn gate(&self, key: TemplateKey) -> Arc<FlightGate> {
        let mut map = self.gates.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= FLIGHT_CAP && !map.contains_key(&key) {
            map.retain(|_, gate| Arc::strong_count(gate) > 1);
        }
        map.entry(key)
            .or_insert_with(|| {
                Arc::new(FlightGate {
                    one: Arc::new(Semaphore::new(1)),
                    slot: Mutex::new(None),
                })
            })
            .clone()
    }

    /// Run `build` off the reactor when `key` is not already stored.
    /// The permit lives in the build task, so dropping this call does not
    /// let a second build of `key` start and does not abort the one in
    /// flight. A template that does not match `key` is not stored.
    pub async fn get_or_build(
        self: &Arc<Self>,
        key: TemplateKey,
        build: impl FnOnce() -> io::Result<Option<Template>> + Send + 'static,
    ) -> io::Result<Option<Template>> {
        let gate = self.gate(key);
        if let Some(hit) = cached(&gate) {
            return Ok(Some(hit));
        }
        let permit = Arc::clone(&gate.one)
            .acquire_owned()
            .await
            .expect("sv2 template flight");
        if let Some(hit) = cached(&gate) {
            drop(permit);
            return Ok(Some(hit));
        }
        let gate = Arc::clone(&gate);
        // Await so this caller sees the result. Dropping the future detaches
        // the task and does not abort it. The permit stays in the task, so a
        // second build of this key still waits.
        let task = tokio::spawn(async move {
            let _permit = permit;
            let built = rbitcoin_net::off_pool(build).await?;
            if let Some(t) = built.clone() {
                if template_matches(&key, &t) {
                    *gate.slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(t);
                }
            }
            Ok(built)
        });
        task.await
            .map_err(|_| io::Error::other("sv2 template flight dropped"))?
    }
}

fn cached(gate: &FlightGate) -> Option<Template> {
    gate.slot.lock().unwrap_or_else(|e| e.into_inner()).clone()
}
