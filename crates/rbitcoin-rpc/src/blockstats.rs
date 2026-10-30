//! Core `getblockstats` — stamped `txstat` rows, reconstruct fallback.

use crate::methods::{
    map_query, parse_hash32_display, rpc_error, RpcContext, RpcParams, ERR_INVALID_ADDRESS_OR_KEY,
    ERR_INVALID_PARAMETER, ERR_MISC,
};
use bitcoin::consensus::encode::VarInt;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Block, BlockHash, OutPoint, ScriptBuf, TxOut};
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::StampedTxstatBlock;
use rbitcoin_store::{HeaderRecord, OutputRecord, TxStatRow};
use serde_json::{json, Map, Value};

/// Weight percentiles reported by `getblockstats` (10 / 25 / 50 / 75 / 90).
#[doc(hidden)]
pub const PERCENTILES: [i64; 5] = [10, 25, 50, 75, 90];

#[doc(hidden)]
pub const HELP: &str = "getblockstats hash_or_height ( stats )";

/// Core `CScript::IsUnspendable`: leading `OP_RETURN`, or over `MAX_SCRIPT_SIZE`.
pub fn is_unspendable(script: &[u8]) -> bool {
    rbitcoin_consensus::policy::is_unspendable(script)
}

#[doc(hidden)]
pub struct StampedExtras {
    pub total_out: i64,
    pub spendable_outs: i64,
    pub n_ins: Vec<u32>,
    pub utxo_size: Option<UtxoSizeInc>,
}

/// Core v32.1 `PER_UTXO_OVERHEAD`: `sizeof(COutPoint) + sizeof(uint32_t)`, the
/// outpoint plus the packed height and coinbase flag.
const PER_UTXO_OVERHEAD: i64 = 40;

/// Core `utxo_size_inc` / `utxo_size_inc_actual`. Each created coin adds its
/// serialized `CTxOut` plus [`PER_UTXO_OVERHEAD`]; each spent prevout
/// subtracts the same. `actual` adds only coins that enter the UTXO set.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UtxoSizeInc {
    pub inc: i64,
    pub actual: i64,
}

impl UtxoSizeInc {
    fn coin_size(script: &[u8]) -> i64 {
        let len = script.len();
        (Amount::SIZE + VarInt::from(len).size() + len) as i64 + PER_UTXO_OVERHEAD
    }

    fn create(&mut self, script: &[u8], enters_utxo_set: bool) {
        let size = Self::coin_size(script);
        self.inc += size;
        if enters_utxo_set {
            self.actual += size;
        }
    }

    fn spend(&mut self, script: &[u8]) {
        let size = Self::coin_size(script);
        self.inc -= size;
        self.actual -= size;
    }
}

/// Only the two size stats need the stamped prevout reads. An empty `stats`
/// selects every stat.
fn selects_utxo_size(want: &[String]) -> bool {
    want.is_empty()
        || want
            .iter()
            .any(|s| matches!(s.as_str(), "utxo_size_inc" | "utxo_size_inc_actual"))
}

/// Outputs Core counts in `utxo_increase_actual`: not height 0, not a
/// BIP30-repeat coinbase, and not an unspendable script.
#[doc(hidden)]
pub fn output_enters_utxo_set(
    height: u32,
    hash: &[u8; 32],
    is_coinbase: bool,
    script: &[u8],
) -> bool {
    if height == 0 {
        return false;
    }
    if is_coinbase {
        let display = BlockHash::from_byte_array(*hash).to_string();
        if matches!(
            (height, display.as_str()),
            (
                91842,
                "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"
            ) | (
                91880,
                "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"
            )
        ) {
            return false;
        }
    }
    !is_unspendable(script)
}

/// Core `CalculateTruncatedMedian`: even length is the integer mean of the two middles.
pub fn truncated_median(mut scores: Vec<i64>) -> i64 {
    let n = scores.len();
    if n == 0 {
        return 0;
    }
    scores.sort_unstable();
    if n.is_multiple_of(2) {
        (scores[n / 2 - 1] + scores[n / 2]) / 2
    } else {
        scores[n / 2]
    }
}

/// Core `CalculatePercentilesByWeight`. `scores` is `(feerate, weight)`.
pub fn percentiles_by_weight(mut scores: Vec<(i64, i64)>, total_weight: i64) -> [i64; 5] {
    let mut result = [0i64; 5];
    if total_weight == 0 {
        return result;
    }
    scores.sort_unstable();
    let mut next = 0usize;
    let mut cumulative = 0i64;
    for (feerate, weight) in scores {
        cumulative += weight;
        while next < 5 && cumulative >= total_weight * PERCENTILES[next] / 100 {
            result[next] = feerate;
            next += 1;
        }
    }
    result
}

/// All `getblockstats` fields for one reconstructed block.
#[derive(Debug, Clone)]
pub struct BlockStats {
    pub avgfee: i64,
    pub avgfeerate: i64,
    pub avgtxsize: i64,
    pub blockhash: String,
    pub feerate_percentiles: [i64; 5],
    pub height: u32,
    pub ins: i64,
    pub maxfee: i64,
    pub maxfeerate: i64,
    pub maxtxsize: i64,
    pub medianfee: i64,
    pub mediantime: u32,
    pub mediantxsize: i64,
    pub minfee: i64,
    pub minfeerate: i64,
    pub mintxsize: i64,
    pub outs: i64,
    pub subsidy: i64,
    pub swtotal_size: i64,
    pub swtotal_weight: i64,
    pub swtxs: i64,
    pub time: u32,
    pub total_out: i64,
    pub total_size: i64,
    pub total_weight: i64,
    pub totalfee: i64,
    pub txs: i64,
    pub utxo_increase: i64,
    /// Spendable outputs minus non-coinbase inputs.
    pub utxo_increase_actual: i64,
    /// `None` when the selected stats skip the stamped prevout reads.
    pub utxo_size: Option<UtxoSizeInc>,
}

impl BlockStats {
    pub fn to_json(&self) -> Value {
        Value::Object(self.to_map())
    }

    #[doc(hidden)]
    pub fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("avgfee".into(), json!(self.avgfee));
        m.insert("avgfeerate".into(), json!(self.avgfeerate));
        m.insert("avgtxsize".into(), json!(self.avgtxsize));
        m.insert("blockhash".into(), json!(self.blockhash.clone()));
        m.insert(
            "feerate_percentiles".into(),
            json!(self.feerate_percentiles.to_vec()),
        );
        m.insert("height".into(), json!(self.height));
        m.insert("ins".into(), json!(self.ins));
        m.insert("maxfee".into(), json!(self.maxfee));
        m.insert("maxfeerate".into(), json!(self.maxfeerate));
        m.insert("maxtxsize".into(), json!(self.maxtxsize));
        m.insert("medianfee".into(), json!(self.medianfee));
        m.insert("mediantime".into(), json!(self.mediantime));
        m.insert("mediantxsize".into(), json!(self.mediantxsize));
        m.insert("minfee".into(), json!(self.minfee));
        m.insert("minfeerate".into(), json!(self.minfeerate));
        m.insert("mintxsize".into(), json!(self.mintxsize));
        m.insert("outs".into(), json!(self.outs));
        m.insert("subsidy".into(), json!(self.subsidy));
        m.insert("swtotal_size".into(), json!(self.swtotal_size));
        m.insert("swtotal_weight".into(), json!(self.swtotal_weight));
        m.insert("swtxs".into(), json!(self.swtxs));
        m.insert("time".into(), json!(self.time));
        m.insert("total_out".into(), json!(self.total_out));
        m.insert("total_size".into(), json!(self.total_size));
        m.insert("total_weight".into(), json!(self.total_weight));
        m.insert("totalfee".into(), json!(self.totalfee));
        m.insert("txs".into(), json!(self.txs));
        m.insert("utxo_increase".into(), json!(self.utxo_increase));
        m.insert(
            "utxo_increase_actual".into(),
            json!(self.utxo_increase_actual),
        );
        if let Some(size) = self.utxo_size {
            m.insert("utxo_size_inc".into(), json!(size.inc));
            m.insert("utxo_size_inc_actual".into(), json!(size.actual));
        }
        m
    }

    #[doc(hidden)]
    pub fn select(&self, stats: &[String]) -> Result<Value, Value> {
        if stats.is_empty() {
            return Ok(self.to_json());
        }
        let all = self.to_map();
        let mut out = Map::new();
        for s in stats {
            match all.get(s) {
                Some(v) => {
                    out.insert(s.clone(), v.clone());
                }
                None => {
                    return Err(rpc_error(
                        ERR_INVALID_PARAMETER,
                        format!("Invalid selected statistic '{s}'"),
                    ));
                }
            }
        }
        Ok(Value::Object(out))
    }
}

/// Sum fees / UTXO / weight for a reconstructed block (same numbers RPC returns).
pub fn compute_block_stats(
    height: u32,
    block: &Block,
    mediantime: u32,
    subsidy: i64,
    prevout: impl Fn(&OutPoint) -> Option<TxOut>,
) -> Result<BlockStats, String> {
    let mut ins = 0i64;
    let mut outs = 0i64;
    let mut spendable_outs = 0i64;
    let block_hash = block.block_hash().to_byte_array();
    let mut total_out = 0i64;
    let mut total_size = 0i64;
    let mut total_weight = 0i64;
    let mut totalfee = 0i64;
    let mut swtotal_size = 0i64;
    let mut swtotal_weight = 0i64;
    let mut swtxs = 0i64;
    let mut fees = Vec::new();
    let mut sizes = Vec::new();
    let mut feerate_weights: Vec<(i64, i64)> = Vec::new();
    let mut minfee = i64::MAX;
    let mut maxfee = 0i64;
    let mut minfeerate = i64::MAX;
    let mut maxfeerate = 0i64;
    let mut mintxsize = i64::MAX;
    let mut maxtxsize = 0i64;
    let mut utxo_size = UtxoSizeInc::default();

    for tx in &block.txdata {
        let is_cb = tx.is_coinbase();
        for o in &tx.output {
            let script = o.script_pubkey.as_bytes();
            let enters = output_enters_utxo_set(height, &block_hash, is_cb, script);
            if enters {
                spendable_outs += 1;
            }
            utxo_size.create(script, enters);
        }
        let tx_size = tx.total_size() as i64;
        let tx_weight = tx.weight().to_wu() as i64;
        let has_wit = tx.input.iter().any(|i| !i.witness.is_empty());

        if !is_cb {
            total_size += tx_size;
            total_weight += tx_weight;
            if has_wit {
                swtxs += 1;
                swtotal_size += tx_size;
                swtotal_weight += tx_weight;
            }
            let mut input_value = 0i64;
            for inp in &tx.input {
                ins += 1;
                let po = prevout(&inp.previous_output)
                    .ok_or_else(|| format!("missing prevout {}", inp.previous_output))?;
                input_value += po.value.to_sat() as i64;
                utxo_size.spend(po.script_pubkey.as_bytes());
            }
            let mut output_value = 0i64;
            for o in &tx.output {
                output_value += o.value.to_sat() as i64;
            }
            total_out += output_value;
            let fee = input_value.saturating_sub(output_value);
            totalfee += fee;
            let feerate = if tx_weight > 0 {
                fee.saturating_mul(4) / tx_weight
            } else {
                0
            };
            fees.push(fee);
            sizes.push(tx_size);
            feerate_weights.push((feerate, tx_weight));
            minfee = minfee.min(fee);
            maxfee = maxfee.max(fee);
            minfeerate = minfeerate.min(feerate);
            maxfeerate = maxfeerate.max(feerate);
            mintxsize = mintxsize.min(tx_size);
            maxtxsize = maxtxsize.max(tx_size);
        }

        outs += tx.output.len() as i64;
    }

    let n_non_cb = fees.len() as i64;
    if n_non_cb == 0 {
        minfee = 0;
        minfeerate = 0;
        mintxsize = 0;
    }
    let avgfee = if n_non_cb > 0 { totalfee / n_non_cb } else { 0 };
    let avgfeerate = if total_weight > 0 {
        totalfee.saturating_mul(4) / total_weight
    } else {
        0
    };
    let avgtxsize = if n_non_cb > 0 {
        total_size / n_non_cb
    } else {
        0
    };

    Ok(BlockStats {
        avgfee,
        avgfeerate,
        avgtxsize,
        blockhash: block.block_hash().to_string(),
        feerate_percentiles: percentiles_by_weight(feerate_weights, total_weight),
        height,
        ins,
        maxfee,
        maxfeerate,
        maxtxsize,
        medianfee: truncated_median(fees),
        mediantime,
        mediantxsize: truncated_median(sizes),
        minfee,
        minfeerate,
        mintxsize,
        outs,
        subsidy,
        swtotal_size,
        swtotal_weight,
        swtxs,
        time: block.header.time,
        total_out,
        total_size,
        total_weight,
        totalfee,
        txs: block.txdata.len() as i64,
        utxo_increase: outs - ins,
        utxo_increase_actual: spendable_outs - ins,
        utxo_size: Some(utxo_size),
    })
}

#[doc(hidden)]
pub fn stats_from_txstat(
    height: u32,
    rec: &HeaderRecord,
    mediantime: u32,
    subsidy: i64,
    rows: &[TxStatRow],
    n_outs: &[u32],
    extras: &StampedExtras,
) -> BlockStats {
    let mut ins = 0i64;
    let mut outs = 0i64;
    let mut total_size = 0i64;
    let mut total_weight = 0i64;
    let mut totalfee = 0i64;
    let mut swtotal_size = 0i64;
    let mut swtotal_weight = 0i64;
    let mut swtxs = 0i64;
    let mut fees = Vec::new();
    let mut sizes = Vec::new();
    let mut feerate_weights: Vec<(i64, i64)> = Vec::new();
    let mut minfee = i64::MAX;
    let mut maxfee = 0i64;
    let mut minfeerate = i64::MAX;
    let mut maxfeerate = 0i64;
    let mut mintxsize = i64::MAX;
    let mut maxtxsize = 0i64;

    for (i, (row, n_out)) in rows.iter().zip(n_outs.iter()).enumerate() {
        outs += i64::from(*n_out);
        let is_cb = i == 0;
        if is_cb {
            continue;
        }
        ins += i64::from(*extras.n_ins.get(i).unwrap_or(&0));
        let tx_size = i64::try_from(row.size()).unwrap_or(i64::MAX);
        let tx_weight = i64::try_from(row.weight()).unwrap_or(i64::MAX);
        let fee = i64::try_from(row.fee_sat).unwrap_or(i64::MAX);
        total_size += tx_size;
        total_weight += tx_weight;
        totalfee += fee;
        let has_wit = row.has_witness();
        if has_wit {
            swtxs += 1;
            swtotal_size += tx_size;
            swtotal_weight += tx_weight;
        }
        let feerate = if tx_weight > 0 {
            fee.saturating_mul(4) / tx_weight
        } else {
            0
        };
        fees.push(fee);
        sizes.push(tx_size);
        feerate_weights.push((feerate, tx_weight));
        minfee = minfee.min(fee);
        maxfee = maxfee.max(fee);
        minfeerate = minfeerate.min(feerate);
        maxfeerate = maxfeerate.max(feerate);
        mintxsize = mintxsize.min(tx_size);
        maxtxsize = maxtxsize.max(tx_size);
    }

    let n_non_cb = fees.len() as i64;
    if n_non_cb == 0 {
        minfee = 0;
        minfeerate = 0;
        mintxsize = 0;
    }
    let avgfee = if n_non_cb > 0 { totalfee / n_non_cb } else { 0 };
    let avgfeerate = if total_weight > 0 {
        totalfee.saturating_mul(4) / total_weight
    } else {
        0
    };
    let avgtxsize = if n_non_cb > 0 {
        total_size / n_non_cb
    } else {
        0
    };

    BlockStats {
        avgfee,
        avgfeerate,
        avgtxsize,
        blockhash: BlockHash::from_byte_array(rec.hash).to_string(),
        feerate_percentiles: percentiles_by_weight(feerate_weights, total_weight),
        height,
        ins,
        maxfee,
        maxfeerate,
        maxtxsize,
        medianfee: truncated_median(fees),
        mediantime,
        mediantxsize: truncated_median(sizes),
        minfee,
        minfeerate,
        mintxsize,
        outs,
        subsidy,
        swtotal_size,
        swtotal_weight,
        swtxs,
        time: rec.timestamp,
        total_out: extras.total_out,
        total_size,
        total_weight,
        totalfee,
        txs: rows.len() as i64,
        utxo_increase: outs - ins,
        utxo_increase_actual: extras.spendable_outs - ins,
        utxo_size: extras.utxo_size,
    }
}

/// Non-coinbase output value, spendable output count, and the created half
/// of [`UtxoSizeInc`] from one read of each stamped tx's outputs.
#[derive(Default)]
struct StampedOutputs {
    total_out: i64,
    spendable: i64,
    created: UtxoSizeInc,
}

impl StampedOutputs {
    fn read(
        query: &rbitcoin_query::Query,
        height: u32,
        block_hash: &[u8; 32],
        fks: &[Fk],
    ) -> Result<Self, rbitcoin_query::QueryError> {
        let mut tally = Self::default();
        for (i, fk) in fks.iter().enumerate() {
            let is_coinbase = i == 0;
            let (_meta, outs) = query.store().get_tx_meta_and_outputs(*fk)?;
            for o in &outs {
                if !is_coinbase {
                    tally.total_out = tally.total_out.saturating_add(o.value as i64);
                }
                let enters = output_enters_utxo_set(height, block_hash, is_coinbase, &o.script);
                if enters {
                    tally.spendable += 1;
                }
                tally.created.create(&o.script, enters);
            }
        }
        Ok(tally)
    }
}

/// Subtract every non-coinbase input's parent coin from `size`. The parent
/// edges are one `input.body` span read; each parent's outputs are read once.
fn spend_stamped_prevouts(
    ctx: &RpcContext,
    height: Height,
    fks: &[Fk],
    mut size: UtxoSizeInc,
) -> Result<UtxoSizeInc, Value> {
    let store_err = |e: rbitcoin_store::StoreError| rpc_error(ERR_MISC, e.to_string());
    let broken = |what: String| {
        rpc_error(
            ERR_MISC,
            format!("invariant: getblockstats height {} {what}", height.0),
        )
    };
    let Some((first, last)) = fks.get(1).zip(fks.last()) else {
        return Ok(size);
    };
    let spans = ctx
        .query
        .store()
        .input_edges_span(first.0, last.0)
        .map_err(store_err)?;
    if spans.len() != fks.len() - 1 {
        return Err(broken("input edge span length".into()));
    }
    let mut prevouts = Vec::new();
    for (fk, edges) in fks[1..].iter().zip(spans) {
        let edges = edges.ok_or_else(|| broken(format!("create {} has no input edges", fk.0)))?;
        for edge in edges {
            if edge.parent.is_null() {
                return Err(broken(format!("create {} input has no parent edge", fk.0)));
            }
            prevouts.push((edge.parent.0, edge.vout));
        }
    }
    prevouts.sort_unstable();
    let mut parent: Option<(u64, Vec<OutputRecord>)> = None;
    for (parent_fk, vout) in prevouts {
        if parent.as_ref().is_none_or(|(fk, _)| *fk != parent_fk) {
            let (_, outs) = ctx
                .query
                .store()
                .get_tx_meta_and_outputs(Fk(parent_fk))
                .map_err(store_err)?;
            parent = Some((parent_fk, outs));
        }
        let out = parent
            .as_ref()
            .and_then(|(_, outs)| outs.get(vout as usize))
            .ok_or_else(|| broken(format!("parent {parent_fk} has no output {vout}")))?;
        size.spend(&out.script);
    }
    Ok(size)
}

#[doc(hidden)]
pub fn help_err() -> Value {
    rpc_error(ERR_MISC, HELP)
}

#[doc(hidden)]
pub fn parse_stats(params: &RpcParams) -> Result<Vec<String>, Value> {
    match params.get(1, "stats") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(a)) => {
            let mut out = Vec::with_capacity(a.len());
            for v in a {
                let s = v.as_str().ok_or_else(|| {
                    rpc_error(ERR_INVALID_PARAMETER, "Invalid parameter, expected string")
                })?;
                out.push(s.to_string());
            }
            Ok(out)
        }
        Some(_) => Err(rpc_error(
            ERR_INVALID_PARAMETER,
            "Invalid parameter, expected array",
        )),
    }
}

#[doc(hidden)]
pub enum HashOrHeight {
    Height(i64),
    Hash([u8; 32]),
}

#[doc(hidden)]
pub fn parse_hash_or_height(v: &Value) -> Result<HashOrHeight, Value> {
    if let Some(n) = v.as_i64() {
        return Ok(HashOrHeight::Height(n));
    }
    if let Some(n) = v.as_u64() {
        return Ok(HashOrHeight::Height(n as i64));
    }
    if let Some(s) = v.as_str() {
        let h = parse_hash32_display(s)
            .map_err(|_| rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found"))?;
        return Ok(HashOrHeight::Hash(h));
    }
    Err(rpc_error(
        ERR_INVALID_PARAMETER,
        "hash_or_height must be a hash string or height",
    ))
}

#[doc(hidden)]
pub type PrevoutMap = std::collections::HashMap<OutPoint, TxOut>;

/// Every non-coinbase input of a connected block resolves: in-block parents
/// from the block, the rest through the spender's `input.body` edges.
#[doc(hidden)]
pub fn prevout_map_for_block(
    ctx: &RpcContext,
    height: Height,
    block: &Block,
) -> Result<PrevoutMap, Value> {
    let store_err = |e: rbitcoin_store::StoreError| rpc_error(ERR_MISC, e.to_string());
    let broken = |what: String| {
        rpc_error(
            ERR_MISC,
            format!("invariant: getblockstats height {} {what}", height.0),
        )
    };
    let mut map = PrevoutMap::new();
    for tx in &block.txdata {
        let tid = tx.compute_txid();
        for (vout, o) in tx.output.iter().enumerate() {
            map.insert(
                OutPoint {
                    txid: tid,
                    vout: vout as u32,
                },
                o.clone(),
            );
        }
    }
    let fks = ctx.query.block_tx_fks(height).map_err(store_err)?;
    if fks.len() != block.txdata.len() {
        return Err(broken("tx count".into()));
    }
    for (tx, fk) in block.txdata.iter().zip(fks).skip(1) {
        let (_, prevs) = ctx
            .query
            .store()
            .get_tx_meta_and_prevouts(fk)
            .map_err(store_err)?;
        if prevs.len() != tx.input.len() {
            return Err(broken(format!("{} input edge count", tx.compute_txid())));
        }
        for (inp, (create_fk, vout)) in tx.input.iter().zip(prevs) {
            let op = inp.previous_output;
            if map.contains_key(&op) {
                continue;
            }
            if create_fk.is_null() {
                return Err(broken(format!(
                    "{} input {op} has no parent edge",
                    tx.compute_txid()
                )));
            }
            let out = ctx
                .query
                .tx_output_at_fk(create_fk, vout)
                .map_err(store_err)?;
            map.insert(
                op,
                TxOut {
                    value: Amount::from_sat(out.value),
                    script_pubkey: ScriptBuf::from_bytes(out.script),
                },
            );
        }
    }
    Ok(map)
}

#[doc(hidden)]
pub fn stats_for_stamped(
    ctx: &RpcContext,
    height: Height,
    stamped: &StampedTxstatBlock,
    want: &[String],
) -> Result<BlockStats, Value> {
    let mediantime = rbitcoin_query::median_time_past(ctx.query.as_ref(), height)
        .unwrap_or(stamped.rec.timestamp);
    let params = match ctx.chain.as_ref() {
        Some(c) => c.params.clone(),
        None => rbitcoin_consensus::ChainParams::for_network(ctx.network),
    };
    let subsidy = rbitcoin_consensus::block_subsidy(height.0, &params);
    let outputs = StampedOutputs::read(
        ctx.query.as_ref(),
        height.0,
        &stamped.rec.hash,
        &stamped.fks,
    )
    .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    let utxo_size = if selects_utxo_size(want) {
        Some(spend_stamped_prevouts(
            ctx,
            height,
            &stamped.fks,
            outputs.created,
        )?)
    } else {
        None
    };
    let extras = StampedExtras {
        total_out: outputs.total_out,
        spendable_outs: outputs.spendable,
        n_ins: {
            let mut v = Vec::with_capacity(stamped.fks.len());
            for &fk in &stamped.fks {
                let n = ctx
                    .query
                    .store()
                    .input_n_in(fk)
                    .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
                    .unwrap_or(0);
                v.push(n);
            }
            v
        },
        utxo_size,
    };
    Ok(stats_from_txstat(
        height.0,
        &stamped.rec,
        mediantime,
        subsidy,
        &stamped.rows,
        &stamped.n_outs,
        &extras,
    ))
}

#[doc(hidden)]
pub fn stats_for_connected(
    ctx: &RpcContext,
    height: Height,
    block: &Block,
    parents: &PrevoutMap,
) -> Result<BlockStats, Value> {
    let mediantime =
        rbitcoin_query::median_time_past(ctx.query.as_ref(), height).unwrap_or(block.header.time);
    let params = match ctx.chain.as_ref() {
        Some(c) => c.params.clone(),
        None => rbitcoin_consensus::ChainParams::for_network(ctx.network),
    };
    let subsidy = rbitcoin_consensus::block_subsidy(height.0, &params);
    compute_block_stats(height.0, block, mediantime, subsidy, |op| {
        parents.get(op).cloned()
    })
    .map_err(|e| rpc_error(ERR_MISC, e))
}

/// `getblockstats hash_or_height ( stats )`
pub fn getblockstats(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["hash_or_height", "stats"])?;
    if params.pos_len() > 2 {
        return Err(help_err());
    }
    let Some(raw) = params.get(0, "hash_or_height") else {
        return Err(help_err());
    };
    let want = parse_stats(params)?;
    let tip = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);

    let height = match parse_hash_or_height(raw)? {
        HashOrHeight::Height(h) => {
            if h < 0 {
                return Err(rpc_error(
                    ERR_INVALID_PARAMETER,
                    format!("Target block height {h} is negative"),
                ));
            }
            if h > i64::from(tip) {
                return Err(rpc_error(
                    ERR_INVALID_PARAMETER,
                    format!("Target block height {h} after current tip {tip}"),
                ));
            }
            Height(h as u32)
        }
        HashOrHeight::Hash(hash) => {
            match ctx
                .query
                .height_of_hash(&hash)
                .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
            {
                Some(height) => height,
                None => {
                    if ctx
                        .query
                        .get_header_by_hash(&hash)
                        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
                        .is_some()
                    {
                        return Err(rpc_error(
                            ERR_MISC,
                            "Block not available (not fully downloaded)",
                        ));
                    }
                    return Err(rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found"));
                }
            }
        }
    };

    if let Some(stamped) = ctx
        .query
        .stamped_txstat_block(height)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
    {
        let stats = stats_for_stamped(ctx, height, &stamped, &want)?;
        return stats.select(&want);
    }

    let block = ctx
        .query
        .reconstruct_block_at_height(height)
        .map_err(|e| map_query(e, "Block not available (pruned data)"))?;
    let parents = prevout_map_for_block(ctx, height, &block)?;
    let _ = ctx.query.stamp_txstat_from_block(height, &block);
    let stats = stats_for_connected(ctx, height, &block, &parents)?;
    stats.select(&want)
}
