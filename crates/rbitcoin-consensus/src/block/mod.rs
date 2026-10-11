#[cfg(test)]
use crate::confirm_phase_stats;
use crate::error::ConsensusError;
use crate::milestone::Milestone;
use crate::params::ChainParams;
use bitcoin::block::Block;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::script::{Script, ScriptBuf};
use bitcoin::{Amount, OutPoint, Transaction, TxOut, Witness};
use rbitcoin_primitives::Height;
use rbitcoin_query::{FkMap, Query, TxidHasher, U32Map, U64Map};
use std::borrow::Borrow;
use std::hash::BuildHasherDefault;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::Instant;

pub struct ValidationContext<'a> {
    pub params: &'a ChainParams,
    pub height: Height,
    pub milestone: Milestone,
    /// When **false** (IBD Class A archive prep): skip height-gated soft-fork
    /// checks that need a reliable tip height — BIP34 coinbase push and
    /// “unexpected witness before segwit”.
    ///
    /// Archive intentionally used `height = GENESIS` as a BIP34 sentinel (resume
    /// could not always trust ordered height). That made **signet** reject every
    /// post-genesis block: Core/Inquisition `SegwitHeight = 1`, so height 0 looks
    /// pre-segwit while BIP325 blocks always carry witness. Soft-fork timing is
    /// enforced at **confirm** with the true height. Merkle, witness
    /// commitment, and weight still run here either way. Commitment is
    /// checked before weight so witness padding is not the block hash's fault.
    pub enforce_height_gates: bool,
}

impl<'a> ValidationContext<'a> {
    /// Full structure + soft-fork gates at `height` (confirm / connect).
    pub fn at(params: &'a ChainParams, height: Height, milestone: Milestone) -> Self {
        Self {
            params,
            height,
            milestone,
            enforce_height_gates: true,
        }
    }

    /// Archive prep: height-independent structure only (see [`Self::enforce_height_gates`]).
    pub fn archive_structure(params: &'a ChainParams) -> Self {
        Self {
            params,
            height: Height::GENESIS,
            milestone: Milestone::NONE,
            enforce_height_gates: false,
        }
    }
}

const MAX_BLOCK_STRIPPED_SIZE: usize = 1_000_000;
/// Consensus block weight limit. Compact-block tx count is this divided by
/// [`MIN_TX_WEIGHT`].
pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
/// Minimum serializable transaction weight (10 bytes × witness scale 4).
pub const MIN_TX_WEIGHT: u64 = 10 * 4;
/// Most transactions a valid block can contain.
pub const MAX_BLOCK_TX_COUNT: usize = (MAX_BLOCK_WEIGHT / MIN_TX_WEIGHT) as usize;

fn check_tx_local(tx: &Transaction, base_size: usize) -> Result<(), ConsensusError> {
    if tx.input.is_empty() {
        return Err(ConsensusError::BadTx("no inputs"));
    }
    if tx.output.is_empty() {
        return Err(ConsensusError::BadTx("no outputs"));
    }
    if base_size > MAX_BLOCK_STRIPPED_SIZE {
        return Err(ConsensusError::BadTx("bad-txns-oversize"));
    }
    let mut seen: rbitcoin_query::OutPointSet =
        rbitcoin_query::OutPointSet::with_capacity_and_hasher(tx.input.len(), Default::default());
    for inp in &tx.input {
        if !tx.is_coinbase() && inp.previous_output.is_null() {
            return Err(ConsensusError::BadTx("bad-txns-prevout-null"));
        }
        let key = (
            inp.previous_output.txid.to_byte_array(),
            inp.previous_output.vout,
        );
        if !seen.insert(key) {
            return Err(ConsensusError::BadTx("bad-txns-inputs-duplicate"));
        }
    }
    Ok(())
}

/// Context-free / structural block checks (no UTXO / prevout).
pub fn validate_block_structure(
    block: &Block,
    ctx: &ValidationContext<'_>,
) -> Result<(), ConsensusError> {
    validate_block_structure_hashed(block, ctx).map(|_| ())
}

/// Core `IsBlockMutated` 64-byte rule. With no coinbase first, a tx whose
/// stripped size is 64 bytes may be an inner merkle node read as a tx, so
/// the body need not be the one the header commits to. Such a block is
/// already invalid; this only decides that its hash is not cached as failed.
pub fn block_mutated_without_coinbase(block: &Block) -> bool {
    if block.txdata.first().is_some_and(Transaction::is_coinbase) {
        return false;
    }
    block.txdata.iter().any(|tx| tx.base_size() == 64)
}

/// Decode consensus-encoded block bytes and run archive-structure checks.
///
/// Junk / truncated wire returns `Err`. Must not panic — fuzz entry.
pub fn check_block_wire(data: &[u8]) -> Result<(), ConsensusError> {
    use bitcoin::consensus::encode::deserialize;
    let block: Block =
        deserialize(data).map_err(|_| ConsensusError::BadBlock("block wire decode"))?;
    let params = ChainParams::regtest();
    validate_block_structure(&block, &ValidationContext::archive_structure(&params))
}

/// Like [`validate_block_structure`], but returns **once-computed** txids for reuse
/// (merkle / dup / archive encode) so callers do not re-hash every tx.
pub fn validate_block_structure_hashed(
    block: &Block,
    ctx: &ValidationContext<'_>,
) -> Result<Vec<[u8; 32]>, ConsensusError> {
    Ok(validate_block_structure_precomputed(block, ctx)?
        .into_iter()
        .map(|p| p.txid)
        .collect())
}

/// Structure checks plus per-tx [`TxPrecompute`] (one walk: txid/wtxid/weight/common SHA256).
pub(crate) fn validate_block_structure_precomputed(
    block: &Block,
    ctx: &ValidationContext<'_>,
) -> Result<Vec<TxPrecompute>, ConsensusError> {
    Ok(validate_block_structure_with_pres(block, ctx, None, None)?.to_vec())
}

fn reject_bad_block_tx_layout(block: &Block, pres: &[TxPrecompute]) -> Result<(), ConsensusError> {
    if block.txdata.is_empty() {
        return Err(ConsensusError::BadBlock("no transactions"));
    }
    if !block.txdata[0].is_coinbase() {
        // Core IsBlockMutated: a 64-byte tx may be an inner merkle node.
        if pres.iter().any(|p| p.base_size == 64) {
            return Err(ConsensusError::BadBlock("merkle mutated by a 64-byte tx"));
        }
        return Err(ConsensusError::BadBlock("first tx not coinbase"));
    }
    for tx in block.txdata.iter().skip(1) {
        if tx.is_coinbase() {
            return Err(ConsensusError::BadBlock("coinbase not first"));
        }
    }
    Ok(())
}

/// Like [`validate_block_structure_precomputed`], reusing lookup-stashed pres
/// when `pres` is `Some` (no second `from_tx`). Length must match `txdata`.
/// Caller Arc is returned as-is (refcount only).
pub fn validate_block_structure_with_pres(
    block: &Block,
    ctx: &ValidationContext<'_>,
    pres: Option<Arc<[TxPrecompute]>>,
    stats: Option<&rbitcoin_query::ConfirmStats>,
) -> Result<Arc<[TxPrecompute]>, ConsensusError> {
    let n = block.txdata.len();
    let (pres, txid_ns) = if let Some(stashed) = pres {
        if stashed.len() != n {
            return Err(ConsensusError::BadBlock("precompute count mismatch"));
        }
        (stashed, 0)
    } else {
        let t_txid = Instant::now();
        let v: Vec<TxPrecompute> = block.txdata.iter().map(TxPrecompute::from_tx).collect();
        (Arc::from(v), t_txid.elapsed().as_nanos() as u64)
    };

    let t_walk = Instant::now();
    // Core CheckMerkleRoot runs before any body rule. A body the header does
    // not commit to is the peer's fault, not the block hash's.
    let txids: Vec<[u8; 32]> = pres.iter().map(|p| p.txid).collect();
    let (merkle, mutated) = rbitcoin_store::merkle_root_mutated(&txids);
    if merkle != block.header.merkle_root.to_byte_array() {
        return Err(ConsensusError::BadBlock("merkle root mismatch"));
    }
    if mutated {
        return Err(ConsensusError::BadBlock("bad-txns-duplicate"));
    }
    reject_bad_block_tx_layout(block, &pres)?;

    // Core CheckTransaction: after the root matches, so a swapped scriptSig is
    // a merkle mismatch, and before ContextualCheckBlock's BIP34 height.
    let cb_ss = block.txdata[0].input[0].script_sig.len();
    if !(2..=100).contains(&cb_ss) {
        return Err(ConsensusError::BadBlock("bad-cb-length"));
    }

    let mut seen: rbitcoin_query::TxidSet =
        rbitcoin_query::TxidSet::with_capacity_and_hasher(n, Default::default());
    for p in pres.iter() {
        if !seen.insert(p.txid) {
            return Err(ConsensusError::BadBlock("duplicate txid"));
        }
    }

    let tx_count_vi = bitcoin::consensus::encode::VarInt(n as u64).size();
    let base = 80usize
        .saturating_add(tx_count_vi)
        .saturating_add(pres.iter().map(|p| p.base_size).sum());
    let total = 80usize
        .saturating_add(tx_count_vi)
        .saturating_add(pres.iter().map(|p| p.total_size).sum());
    let weight_wu = (base.saturating_mul(3).saturating_add(total)) as u64;
    if base > MAX_BLOCK_STRIPPED_SIZE {
        return Err(ConsensusError::BadBlock("block stripped size too large"));
    }
    // CheckBlock tx shape before malleation. An empty vin is "no inputs",
    // not a missing witness commitment.
    for (tx, p) in block.txdata.iter().zip(pres.iter()) {
        check_tx_local(tx, p.base_size)?;
    }
    // Witness bytes are not in the block hash. Check them before weight so
    // padding cannot be cached as a failed hash.
    reject_witness_malleation(block, ctx, pres.as_ref())?;
    if weight_wu > MAX_BLOCK_WEIGHT {
        return Err(ConsensusError::BadBlock("block weight too large"));
    }

    // BIP34 only after the network's buried height (mainnet 227931). From
    // height 1 this rejects mainnet block 1.
    if ctx.enforce_height_gates && ctx.params.bip34_active_at(ctx.height.0) {
        check_bip34_coinbase(&block.txdata[0], ctx.height.0)?;
    }

    // Money-range gate on the precompute path. `assemble_tx_value_out` applies
    // the same per-output check when a tx has no precompute row.
    for (tx, p) in block.txdata.iter().zip(pres.iter()) {
        for o in &tx.output {
            if exceeds_max_money(o.value.to_sat()) {
                return Err(ConsensusError::BadBlock("bad-txns-vout-toolarge"));
            }
        }
        if exceeds_max_money(p.out_sum) {
            return Err(ConsensusError::BadBlock("bad-txns-txouttotal-toolarge"));
        }
    }

    {
        const WITNESS_SCALE: u64 = 4;
        const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;
        let mut cost = 0u64;
        for p in pres.iter() {
            cost = cost.saturating_add(p.sigops.saturating_mul(WITNESS_SCALE));
        }
        if cost > MAX_BLOCK_SIGOPS_COST {
            return Err(ConsensusError::BadBlock("bad-blk-sigops"));
        }
    }
    let walk_ns = t_walk.elapsed().as_nanos() as u64;

    if let Some(stats) = stats {
        stats.note_struct_parts(txid_ns, 0, walk_ns);
    }

    // BIP325 signet solution is not checked here — tip confirm only.

    Ok(pres)
}

/// Witness commitment before weight. Padding is not the block hash's fault.
fn reject_witness_malleation(
    block: &Block,
    ctx: &ValidationContext<'_>,
    pres: &[TxPrecompute],
) -> Result<(), ConsensusError> {
    let has_witness_data = block_has_witness_from_pres(pres);
    let has_commitment = coinbase_has_witness_commitment(block);
    if has_witness_data && ctx.enforce_height_gates && !ctx.params.segwit_active_at(ctx.height.0) {
        return Err(ConsensusError::BadBlock("unexpected witness before segwit"));
    }
    if (has_witness_data || has_commitment)
        && (ctx.params.segwit_active_at(ctx.height.0) || !ctx.enforce_height_gates)
    {
        let non_cb: Vec<[u8; 32]> = pres.iter().skip(1).map(|p| p.wtxid).collect();
        check_witness_commitment_with_wtxids(block, &non_cb)?;
    }
    Ok(())
}

fn coinbase_has_witness_commitment(block: &Block) -> bool {
    block
        .txdata
        .first()
        .and_then(witness_commitment_vout_index)
        .is_some()
}

/// Last BIP141 `OP_RETURN` witness commitment (exact 38-byte `6a24aa21a9ed` prefix).
pub fn witness_commitment_vout_index(coinbase: &Transaction) -> Option<usize> {
    const MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    coinbase
        .output
        .iter()
        .enumerate()
        .rev()
        .find_map(|(i, out)| {
            let b = out.script_pubkey.as_bytes();
            (b.len() >= 38 && b[..6] == MAGIC).then_some(i)
        })
}

/// True if any input carries witness data.
#[inline]
pub fn block_has_witness(block: &Block) -> bool {
    block
        .txdata
        .iter()
        .any(|tx| tx.input.iter().any(|i| !i.witness.is_empty()))
}

/// Same as [`block_has_witness`] from [`TxPrecompute::has_witness`] (no second walk).
#[inline]
pub fn block_has_witness_from_pres(pres: &[TxPrecompute]) -> bool {
    pres.iter().any(|p| p.has_witness)
}

/// BIP141 coinbase `OP_RETURN` script for GBT `default_witness_commitment`.
pub fn witness_commitment_script(
    non_cb_wtxids: impl IntoIterator<Item = [u8; 32]>,
    reserved: &[u8; 32],
) -> Vec<u8> {
    const MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    let mut leaves = vec![[0u8; 32]];
    leaves.extend(non_cb_wtxids);
    let witness_root = merkle_root_bytes(&leaves);
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&witness_root);
    buf[32..].copy_from_slice(reserved);
    let hash = sha256d::Hash::hash(&buf);
    let mut spk = Vec::with_capacity(38);
    spk.extend_from_slice(&MAGIC);
    spk.extend_from_slice(&hash.to_byte_array());
    spk
}

/// BIP141: set coinbase reserved witness + `OP_RETURN` commitment (nonce = zeros).
///
/// Updates `header.merkle_root`. Caller still grinds PoW. No-op when no witness.
pub fn apply_witness_commitment(block: &mut Block) {
    if !block_has_witness(block) || block.txdata.is_empty() {
        return;
    }
    let reserved = [0u8; 32];
    block.txdata[0].input[0].witness = Witness::from_slice(&[reserved.to_vec()]);
    let wtxids = block
        .txdata
        .iter()
        .skip(1)
        .map(|tx| tx.compute_wtxid().to_byte_array());
    let spk = witness_commitment_script(wtxids, &reserved);
    block.txdata[0].output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(spk),
    });
    if let Some(root) = block.compute_merkle_root() {
        block.header.merkle_root = root;
    }
}

/// Core-style legacy sigop count (CHECKSIG=1, CHECKMULTISIG=20 or accurate N).
pub fn legacy_sigop_count(tx: &Transaction) -> u64 {
    let mut n = 0u64;
    for inp in &tx.input {
        n = n.saturating_add(script_sigop_count(inp.script_sig.as_bytes(), false));
    }
    for out in &tx.output {
        n = n.saturating_add(script_sigop_count(out.script_pubkey.as_bytes(), false));
    }
    n
}

pub(crate) use rbitcoin_primitives::script_sigop_count;

/// Last push in a script for P2SH/BIP141 sigops.
///
/// Opcode `> OP_16` or a truncated push → no redeem (0 sigops). OP_N / OP_1NEGATE
/// count as an empty push.
fn last_script_push(script: &[u8]) -> Option<&[u8]> {
    let mut i = 0usize;
    let mut last: &[u8] = &[];
    while i < script.len() {
        let opcode = script[i];
        i += 1;
        if opcode > 0x60 {
            return None;
        }
        if opcode <= 0x4b {
            let push = opcode as usize;
            if i.saturating_add(push) > script.len() {
                return None;
            }
            last = &script[i..i + push];
            i += push;
        } else if opcode == 0x4c {
            if i >= script.len() {
                return None;
            }
            let push = script[i] as usize;
            i += 1;
            if i.saturating_add(push) > script.len() {
                return None;
            }
            last = &script[i..i + push];
            i += push;
        } else if opcode == 0x4d {
            if i + 1 >= script.len() {
                return None;
            }
            let push = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
            i += 2;
            if i.saturating_add(push) > script.len() {
                return None;
            }
            last = &script[i..i + push];
            i += push;
        } else if opcode == 0x4e {
            if i + 3 >= script.len() {
                return None;
            }
            let push = u32::from_le_bytes(script[i..i + 4].try_into().unwrap_or([0; 4])) as usize;
            i += 4;
            if i.saturating_add(push) > script.len() {
                return None;
            }
            last = &script[i..i + push];
            i += push;
        } else {
            last = &[];
        }
    }
    Some(last)
}

fn is_p2sh_script(spk: &[u8]) -> bool {
    spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87
}

fn is_p2wpkh_program(prog: &[u8]) -> bool {
    prog.len() == 22 && prog[0] == 0x00 && prog[1] == 0x14
}

fn is_p2wsh_program(prog: &[u8]) -> bool {
    prog.len() == 34 && prog[0] == 0x00 && prog[1] == 0x20
}

/// BIP16 P2SH sigops from redeem scripts (accurate CHECKMULTISIG count).
fn p2sh_sigops_one(inp: &bitcoin::TxIn, spk: &[u8]) -> u64 {
    if !is_p2sh_script(spk) {
        return 0;
    }
    last_script_push(inp.script_sig.as_bytes())
        .map(|redeem| script_sigop_count(redeem, true))
        .unwrap_or(0)
}

#[cfg(test)]
fn p2sh_sigop_count(tx: &Transaction, prev_spks: &[&[u8]]) -> u64 {
    let mut n = 0u64;
    for (i, inp) in tx.input.iter().enumerate() {
        let Some(spk) = prev_spks.get(i) else {
            continue;
        };
        n = n.saturating_add(p2sh_sigops_one(inp, spk));
    }
    n
}

/// BIP141 witness sigop count (not witness-scaled).
fn witness_sigops_one(inp: &bitcoin::TxIn, spk: &[u8]) -> u64 {
    let mut program = spk;
    if is_p2sh_script(program) {
        if let Some(redeem) = last_script_push(inp.script_sig.as_bytes()) {
            program = redeem;
        } else {
            return 0;
        }
    }
    if is_p2wpkh_program(program) {
        1
    } else if is_p2wsh_program(program) {
        inp.witness
            .last()
            .map(|ws| script_sigop_count(ws, true))
            .unwrap_or(0)
    } else {
        0
    }
}

#[cfg(test)]
fn witness_sigop_count(tx: &Transaction, prev_spks: &[&[u8]]) -> u64 {
    let mut n = 0u64;
    for (i, inp) in tx.input.iter().enumerate() {
        let Some(spk) = prev_spks.get(i) else {
            continue;
        };
        n = n.saturating_add(witness_sigops_one(inp, spk));
    }
    n
}

fn prevout_spk_sigops(inp: &bitcoin::TxIn, spk: &[u8], bip16: bool, witness: bool) -> u64 {
    const WITNESS_SCALE: u64 = 4;
    let mut n = 0u64;
    if bip16 {
        n = n.saturating_add(p2sh_sigops_one(inp, spk).saturating_mul(WITNESS_SCALE));
    }
    if witness {
        n = n.saturating_add(witness_sigops_one(inp, spk));
    }
    n
}

/// Full Core-style sigop cost for one tx given prevout scripts (BIP16 + BIP141).
pub fn tx_sigop_cost(tx: &Transaction, prev_spks: &[&[u8]], bip16: bool, witness: bool) -> u64 {
    const WITNESS_SCALE: u64 = 4;
    let mut cost = legacy_sigop_count(tx).saturating_mul(WITNESS_SCALE);
    for (i, inp) in tx.input.iter().enumerate() {
        let Some(spk) = prev_spks.get(i) else {
            continue;
        };
        cost = cost.saturating_add(prevout_spk_sigops(inp, spk, bip16, witness));
    }
    cost
}

/// BIP141: coinbase must commit to witness merkle root when segwit is used.
///
/// `precomputed_non_cb` is wtxids for non-coinbase txs (same order as `txdata[1..]`).
fn check_witness_commitment_with_wtxids(
    block: &Block,
    precomputed_non_cb: &[[u8; 32]],
) -> Result<(), ConsensusError> {
    let coinbase = &block.txdata[0];
    let Some(cidx) = witness_commitment_vout_index(coinbase) else {
        return Err(ConsensusError::BadBlock("missing witness commitment"));
    };
    let b = coinbase.output[cidx].script_pubkey.as_bytes();
    let mut committed = [0u8; 32];
    committed.copy_from_slice(&b[6..38]);

    if precomputed_non_cb.len() != block.txdata.len().saturating_sub(1) {
        return Err(ConsensusError::BadBlock("wtxid count mismatch"));
    }
    // Witness merkle: coinbase wtxid is 32 zero bytes.
    let mut leaves = Vec::with_capacity(block.txdata.len());
    leaves.push([0u8; 32]);
    leaves.extend_from_slice(precomputed_non_cb);
    let witness_root = merkle_root_bytes(&leaves);
    let wit = &coinbase.input[0].witness;
    if wit.len() != 1 {
        return Err(ConsensusError::BadBlock("bad-witness-nonce-size"));
    }
    let reserved = wit
        .nth(0)
        .ok_or(ConsensusError::BadBlock("bad-witness-nonce-size"))?;
    if reserved.len() != 32 {
        return Err(ConsensusError::BadBlock("bad-witness-nonce-size"));
    }
    let mut buf = [0u8; 64];
    buf[0..32].copy_from_slice(&witness_root);
    buf[32..64].copy_from_slice(reserved);
    let hash = sha256d::Hash::hash(&buf);
    if hash.to_byte_array() != committed {
        return Err(ConsensusError::BadBlock("witness commitment mismatch"));
    }
    Ok(())
}

/// Merkle root over 32-byte leaves (txid or wtxid tree). Public for tests.
pub(crate) fn merkle_root_bytes(leaves: &[[u8; 32]]) -> [u8; 32] {
    rbitcoin_store::merkle_root_from_txids(leaves)
}

/// BIP34: coinbase scriptSig must start with the block height as a script integer
/// push: 0 → `OP_0`; 1..=16 → `OP_1`..=`OP_16`; else minimal sign-aware little-endian.
pub(crate) fn check_bip34_coinbase(
    coinbase: &Transaction,
    height: u32,
) -> Result<(), ConsensusError> {
    let script = &coinbase.input[0].script_sig;
    let bytes = script.as_bytes();
    if bytes.is_empty() {
        return Err(ConsensusError::BadBlock("bip34 coinbase script empty"));
    }
    let expected = bip34_height_script(height);
    if bytes.len() < expected.len() || &bytes[..expected.len()] != expected.as_slice() {
        return Err(ConsensusError::BadBlock("bip34 height encoding"));
    }
    Ok(())
}

/// Serialize `height` the same way Core pushes it into the coinbase scriptSig.
#[must_use]
pub fn bip34_height_script(height: u32) -> Vec<u8> {
    if height == 0 {
        return vec![0x00];
    }
    if (1..=16).contains(&height) {
        return vec![0x50 + height as u8];
    }
    // Height is at least 17, so the little-endian body is never empty.
    let mut num = Vec::new();
    let mut n = height;
    while n > 0 {
        num.push((n & 0xff) as u8);
        n >>= 8;
    }
    if num.last().unwrap() & 0x80 != 0 {
        num.push(0x00);
    }
    let mut out = Vec::with_capacity(1 + num.len());
    out.push(num.len() as u8);
    out.extend_from_slice(&num);
    out
}

/// One non-coinbase tx ready for script/sig verification (prevouts already resolved).
///
/// Mainnet BIP16 exception block (never enforce P2SH redeem), Core `BIP16Exception`.
/// Height 170060 — pre-activation spends of HASH160/EQUAL as bare scripts.
pub const BIP16_EXCEPTION_MAINNET: [u8; 32] = [
    // little-endian display hash 00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22
    0x22, 0x9c, 0x4f, 0xac, 0x88, 0xba, 0xb1, 0x94, 0xeb, 0x08, 0xf1, 0xa5, 0x28, 0xcc, 0x30, 0x8d,
    0xed, 0x23, 0x97, 0xf4, 0xf4, 0xeb, 0x6e, 0x75, 0xdc, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Mainnet taproot exception, Core `TAPROOT_EXCEPTION` (height 692261).
///
/// `GetBlockScriptFlags` starts from `P2SH|WITNESS` for this hash.
/// Little-endian display hash
/// `0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad`.
pub const TAPROOT_EXCEPTION_MAINNET: [u8; 32] = [
    0xad, 0x95, 0xe3, 0xa1, 0x5e, 0xe5, 0xff, 0xd5, 0x85, 0xc5, 0xe8, 0x1d, 0x44, 0xb5, 0x6a, 0x98,
    0x1e, 0x84, 0x2d, 0x5b, 0xc3, 0x14, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Testnet3 BIP16 exception block, Core `CTestNetParams` `script_flag_exceptions`.
const BIP16_EXCEPTION_TESTNET3: [u8; 32] = [
    // little-endian display hash 00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105
    0x05, 0xb1, 0x32, 0xa4, 0xf7, 0x4a, 0x87, 0x99, 0xa5, 0x7a, 0x42, 0x02, 0xd0, 0xee, 0xb0, 0x96,
    0x12, 0xcc, 0x08, 0xd2, 0x95, 0x40, 0x1f, 0x00, 0x7c, 0x45, 0x30, 0xdd, 0x00, 0x00, 0x00, 0x00,
];

/// BIP16 P2SH from **precomputed** prev MTP + block hash (no header re-walk, no rehash).
///
/// Callers must pass the same prev-block MTP used for BIP113 / header MTP checks
/// and the once-computed block hash (plan `meta.hash` / structure).
#[inline]
pub(crate) fn bip16_active_from_prev_mtp(
    params: &ChainParams,
    height: u32,
    block_hash: &[u8; 32],
    prev_mtp: u32,
) -> bool {
    if *block_hash == BIP16_EXCEPTION_MAINNET {
        return false;
    }
    if params.network == bitcoin::Network::Testnet && *block_hash == BIP16_EXCEPTION_TESTNET3 {
        return false;
    }
    if height == 0 {
        return false;
    }
    // Modern Core buries P2SH: validation.cpp sets SCRIPT_VERIFY_P2SH on every
    // block except the named per-network exceptions (handled above). The
    // historical "prev MTP >= 2012-04-01" gate is gone — keeping it splits
    // from Core on regtest and any early-MTP chain (redeemScript never runs).
    let _ = prev_mtp;
    true
}

/// Transaction held by a [`ScriptCheckJob`].
///
/// Confirm path uses [`JobTx::shared`] so jobs borrow the wire [`Arc<Block>`]
/// (refcount only — no deep `Transaction` clone). Tests/benches use [`JobTx::owned`].
///
/// Deref to [`Transaction`] so script paths keep `job.tx.input` / `&job.tx` ergonomics.
#[derive(Clone)]
pub(crate) struct JobTx {
    inner: JobTxInner,
}

#[derive(Clone)]
enum JobTxInner {
    Owned(Transaction),
    Shared { block: Arc<Block>, index: usize },
}

impl JobTx {
    #[inline]
    pub(crate) fn owned(tx: Transaction) -> Self {
        Self {
            inner: JobTxInner::Owned(tx),
        }
    }

    #[inline]
    pub(crate) fn shared(block: Arc<Block>, index: usize) -> Self {
        debug_assert!(index < block.txdata.len());
        Self {
            inner: JobTxInner::Shared { block, index },
        }
    }

    fn output_at(&self, tx_index: u32, vout: u32) -> Option<&TxOut> {
        match &self.inner {
            JobTxInner::Shared { block, .. } => block
                .txdata
                .get(tx_index as usize)?
                .output
                .get(vout as usize),
            JobTxInner::Owned(_) => None,
        }
    }
}

impl Deref for JobTx {
    type Target = Transaction;
    #[inline]
    fn deref(&self) -> &Transaction {
        match &self.inner {
            JobTxInner::Owned(t) => t,
            JobTxInner::Shared { block, index } => &block.txdata[*index],
        }
    }
}

impl DerefMut for JobTx {
    #[inline]
    fn deref_mut(&mut self) -> &mut Transaction {
        match &mut self.inner {
            JobTxInner::Owned(t) => t,
            JobTxInner::Shared { .. } => {
                panic!("ScriptCheckJob shared wire tx is immutable")
            }
        }
    }
}

impl From<Transaction> for JobTx {
    #[inline]
    fn from(tx: Transaction) -> Self {
        Self::owned(tx)
    }
}

impl Borrow<Transaction> for JobTx {
    #[inline]
    fn borrow(&self) -> &Transaction {
        self.deref()
    }
}

impl AsRef<Transaction> for JobTx {
    #[inline]
    fn as_ref(&self) -> &Transaction {
        self.deref()
    }
}

/// Consensus + standardness flags for one script-verify job.
///
/// Field reads in the interpreter stay a direct bool test (no extra per-opcode
/// branch). Production confirm uses [`Self::consensus_at`]; Core JSON fixtures
/// use [`Self::ALL`] or an explicit struct literal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScriptVerifyFlags {
    pub bip65_active: bool,
    pub bip112_active: bool,
    pub bip66_active: bool,
    pub bip16_active: bool,
    pub taproot_active: bool,
    pub minimal_if: bool,
    pub nullfail: bool,
    pub low_s: bool,
    pub strictenc: bool,
    pub null_dummy: bool,
    pub minimal_data: bool,
    pub witness_pubkeytype: bool,
    pub witness_active: bool,
    pub discourage_upgradable_witness: bool,
    pub const_scriptcode: bool,
    /// SCRIPT_VERIFY_CLEANSTACK for legacy bare and P2SH. Witness v0 already
    /// requires a clean stack. Production confirm leaves this off.
    pub cleanstack: bool,
}

impl ScriptVerifyFlags {
    /// Buried-fork knobs + production standardness defaults (`from_parts`).
    pub const fn buried(
        bip65_active: bool,
        bip112_active: bool,
        bip66_active: bool,
        bip16_active: bool,
        taproot_active: bool,
    ) -> Self {
        Self {
            bip65_active,
            bip112_active,
            bip66_active,
            bip16_active,
            taproot_active,
            minimal_if: false,
            nullfail: false,
            low_s: false,
            strictenc: false,
            null_dummy: true,
            minimal_data: false,
            witness_pubkeytype: false,
            witness_active: true,
            discourage_upgradable_witness: false,
            const_scriptcode: false,
            cleanstack: false,
        }
    }

    /// Core `GetBlockScriptFlags` for `block_hash` at `ctx`. `bip16_active` is
    /// false only for a BIP16 exception block or genesis.
    #[inline]
    pub fn consensus_at(
        ctx: &ValidationContext<'_>,
        block_hash: &[u8; 32],
        bip16_active: bool,
    ) -> Self {
        let h = ctx.height.0;
        // Core sets P2SH|WITNESS|TAPROOT on every block. An exception hash
        // replaces that set: the BIP16 exception (`!bip16_active`) gets none,
        // the Taproot exception gets P2SH|WITNESS.
        let witness_active = bip16_active;
        let taproot_active = bip16_active && *block_hash != TAPROOT_EXCEPTION_MAINNET;
        Self {
            bip65_active: ctx.params.bip65_active_at(h),
            bip112_active: ctx.params.csv_active_at(h),
            bip66_active: ctx.params.bip66_active_at(h),
            bip16_active,
            taproot_active,
            minimal_if: false,
            nullfail: false,
            low_s: false,
            strictenc: false,
            null_dummy: ctx.params.segwit_active_at(h),
            minimal_data: false,
            witness_pubkeytype: false,
            witness_active,
            discourage_upgradable_witness: false,
            const_scriptcode: false,
            cleanstack: false,
        }
    }

    /// Flags a confirm of this block would use: BIP16 from the exception hash,
    /// then [`Self::consensus_at`]. Policy flags stay off.
    #[inline]
    pub fn for_block(
        params: &ChainParams,
        height: u32,
        block_hash: &[u8; 32],
        prev_mtp: u32,
    ) -> Self {
        let bip16 = bip16_active_from_prev_mtp(params, height, block_hash, prev_mtp);
        let ctx = ValidationContext::at(params, Height(height), Milestone::NONE);
        Self::consensus_at(&ctx, block_hash, bip16)
    }
}

/// Prevout scripts for one script job.
///
/// Owned jobs (tests, non-wire connect) store [`TxOut`]. Confirm jobs store
/// [`rbitcoin_query::SharedPrevoutScript`]: same-block bytes stay in the wire
/// block, historical bytes stay in the pin outs `Arc`.
#[derive(Clone, Debug)]
pub(crate) enum JobPrevouts {
    Owned(Vec<TxOut>),
    Shared(Vec<rbitcoin_query::SharedPrevoutScript>),
}

fn shared_slot_eq(
    left: &rbitcoin_query::SharedPrevoutScript,
    right: &rbitcoin_query::SharedPrevoutScript,
) -> bool {
    use rbitcoin_query::SharedPrevoutScript::{Pinned, Wire};
    match (left, right) {
        (
            Wire {
                tx_index: t0,
                vout: v0,
            },
            Wire {
                tx_index: t1,
                vout: v1,
            },
        ) => t0 == t1 && v0 == v1,
        (Pinned(_), Pinned(_)) => left.parts() == right.parts(),
        _ => false,
    }
}

impl PartialEq for JobPrevouts {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Owned(a), Self::Owned(b)) => a == b,
            (Self::Shared(a), Self::Shared(b)) => {
                a.len() == b.len()
                    && a.iter()
                        .zip(b)
                        .all(|(left, right)| shared_slot_eq(left, right))
            }
            _ => false,
        }
    }
}

impl Eq for JobPrevouts {}

impl JobPrevouts {
    pub(crate) fn owned(v: Vec<TxOut>) -> Self {
        Self::Owned(v)
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Owned(v) => v.len(),
            Self::Shared(v) => v.len(),
        }
    }
}

/// Script-verify job for one non-coinbase create.
///
/// Confirm assemble attaches the wire [`Arc<Block>`] (no tx deep-clone). `txid`
/// is the structure/plan hash so scripts can probe mempool preverified without
/// re-hashing.
pub struct ScriptCheckJob {
    /// Wire txid (assemble / [`Self::new`]); used for mempool preverified skip.
    pub(crate) txid: [u8; 32],
    pub(crate) prevouts: JobPrevouts,
    /// Owned (tests) or shared wire block + index (confirm path).
    pub(crate) tx: JobTx,
    pub(crate) flags: ScriptVerifyFlags,
    /// Lookup/structure `TxPrecompute`. Set on the confirm path; tests lazy-`from_tx`.
    pub(crate) pre: std::sync::OnceLock<JobPre>,
}

impl Deref for ScriptCheckJob {
    type Target = ScriptVerifyFlags;
    fn deref(&self) -> &Self::Target {
        &self.flags
    }
}

impl DerefMut for ScriptCheckJob {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.flags
    }
}

/// Confirm jobs borrow the lookup/structure slice; tests own an `Arc`.
pub(crate) enum JobPre {
    Owned(std::sync::Arc<rbitcoin_query::TxPrecompute>),
    Slice {
        slice: std::sync::Arc<[rbitcoin_query::TxPrecompute]>,
        idx: usize,
    },
}

impl ScriptCheckJob {
    /// Build a job hashing `tx` once for [`Self::txid`] (tests / detached verify).
    #[inline]
    pub fn new(prevouts: Vec<TxOut>, tx: Transaction, flags: ScriptVerifyFlags) -> Self {
        use bitcoin::hashes::Hash;
        let txid = tx.compute_txid().to_byte_array();
        Self::with_txid(txid, prevouts, tx, flags)
    }

    /// Owned-tx path (tests / benches / unit connect): reuse precomputed txid.
    #[inline]
    pub(crate) fn with_txid(
        txid: [u8; 32],
        prevouts: Vec<TxOut>,
        tx: Transaction,
        flags: ScriptVerifyFlags,
    ) -> Self {
        Self::from_parts(txid, JobPrevouts::owned(prevouts), JobTx::owned(tx), flags)
    }

    /// Single construction site for activation + production standardness defaults.
    #[inline]
    pub(crate) fn from_parts(
        txid: [u8; 32],
        prevouts: JobPrevouts,
        tx: JobTx,
        flags: ScriptVerifyFlags,
    ) -> Self {
        Self {
            txid,
            prevouts,
            tx,
            flags,
            pre: std::sync::OnceLock::new(),
        }
    }

    /// Confirm assemble: `slice[idx]` by refcount only (no `TxPrecompute` clone).
    #[inline]
    pub(crate) fn with_pre_slice(
        self,
        slice: std::sync::Arc<[rbitcoin_query::TxPrecompute]>,
        idx: usize,
    ) -> Self {
        let _ = self.pre.set(JobPre::Slice { slice, idx });
        self
    }

    fn job_pre(&self) -> &JobPre {
        self.pre.get_or_init(|| {
            JobPre::Owned(std::sync::Arc::new(rbitcoin_query::TxPrecompute::from_tx(
                &self.tx,
            )))
        })
    }

    /// Amount and script bytes for input `i`.
    ///
    /// Shared wire prevouts read the job's block. Pinned prevouts read the outs
    /// `Arc`. A missing vout is `Corrupt`, not an empty script.
    pub(crate) fn prevout_parts(&self, i: usize) -> Result<(i64, &[u8]), ConsensusError> {
        match &self.prevouts {
            JobPrevouts::Owned(v) => {
                let o =
                    v.get(i)
                        .ok_or(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                            "invariant: prevout index",
                        )))?;
                Ok((o.value.to_sat() as i64, o.script_pubkey.as_bytes()))
            }
            JobPrevouts::Shared(v) => {
                let slot =
                    v.get(i)
                        .ok_or(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                            "invariant: prevout index",
                        )))?;
                match slot {
                    rbitcoin_query::SharedPrevoutScript::Wire { tx_index, vout } => {
                        let o = self.wire_output(*tx_index, *vout)?;
                        Ok((o.value.to_sat() as i64, o.script_pubkey.as_bytes()))
                    }
                    rbitcoin_query::SharedPrevoutScript::Pinned(_) => {
                        slot.parts().ok_or(ConsensusError::Store(
                            rbitcoin_store::StoreError::Corrupt("invariant: pinned prevout vout"),
                        ))
                    }
                }
            }
        }
    }

    fn wire_output(&self, tx_index: u32, vout: u32) -> Result<&TxOut, ConsensusError> {
        self.tx
            .output_at(tx_index, vout)
            .ok_or(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                "invariant: wire prevout",
            )))
    }

    #[inline]
    pub(crate) fn prevout_script(&self, i: usize) -> Result<&[u8], ConsensusError> {
        self.prevout_parts(i).map(|(_, script)| script)
    }

    #[inline]
    pub(crate) fn prevout_amount(&self, i: usize) -> Result<Amount, ConsensusError> {
        self.prevout_parts(i)
            .map(|(value, _)| Amount::from_sat(value as u64))
    }

    #[inline]
    pub(crate) fn pre(&self) -> &rbitcoin_query::TxPrecompute {
        match self.job_pre() {
            JobPre::Owned(a) => a.as_ref(),
            JobPre::Slice { slice, idx } => &slice[*idx],
        }
    }
}

/// Identity-hashed `txid → V` (assemble index / pack creates).
pub(crate) type TxidMap<V> = std::collections::HashMap<[u8; 32], V, BuildHasherDefault<TxidHasher>>;

/// Pack-local create fk by parent txid (not per-vout — fk is per tx).
pub(crate) type PendingCreates = TxidMap<rbitcoin_primitives::Fk>;

/// Block-local prevout path counts; flush to [`Query::confirm_stats`] once.
#[derive(Default)]
struct AsmPrevoutAcc {
    in_n: u64,
    same_n: u64,
    batch_n: u64,
    cold_n: u64,
    cold_null_fk_n: u64,
    cold_not_pin_n: u64,
    cold_txid_mismatch_n: u64,
    cold_vout_miss_n: u64,
}

impl AsmPrevoutAcc {
    fn flush(&self, stats: &rbitcoin_query::ConfirmStats) {
        rbitcoin_query::note_confirm(&stats.asm_in_n, self.in_n);
        rbitcoin_query::note_confirm(&stats.asm_prev_same_n, self.same_n);
        rbitcoin_query::note_confirm(&stats.asm_prev_batch_n, self.batch_n);
        rbitcoin_query::note_confirm(&stats.asm_prev_cold_n, self.cold_n);
        rbitcoin_query::note_confirm(&stats.asm_prev_cold_null_fk_n, self.cold_null_fk_n);
        rbitcoin_query::note_confirm(&stats.asm_prev_cold_not_pin_n, self.cold_not_pin_n);
        rbitcoin_query::note_confirm(
            &stats.asm_prev_cold_txid_mismatch_n,
            self.cold_txid_mismatch_n,
        );
        rbitcoin_query::note_confirm(&stats.asm_prev_cold_vout_miss_n, self.cold_vout_miss_n);
    }
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
#[allow(clippy::type_complexity)] // packed row / pin / script-hash tuple is the on-disk shape
/// Sequential assemble: resolve prevout **content**, build script jobs, collect spends.
///
/// Confirm IBD path: no durable spentness / maturity / BIP68 create-height
/// resolution — those run in [`structural_validate_spends`] after scripts (load
/// must not walk create height per parent). Absolute nLockTime finality
/// (BIP113 MTP of prev block) still runs here — it only needs header MTP.
///
/// `pending_spent`: pack-local double-spend (early reject before scripts).
/// `pending_creates`: pack-local `txid → create_fk` (not per-vout).
/// Same-block outs use `txid_index` (this block, `pj < ti`); meters flush
/// once per block (no per-input Instant / atomics).
///
/// Prevouts resolve from per-batch [`rbitcoin_query::BatchParents`] +
/// [`rbitcoin_query::SpendEdges`]. Optimistic miss is `invariant:` (no head recover).
///
/// Returns `(script_jobs, spends, fees, tx_fees)`. `fees` is the block sum
/// for the coinbase subsidy check. `tx_fees` is one satoshi fee per tx
/// (coinbase is 0) for the `txstat` stamp.
///
/// `prev_mtp` / `block_hash` / `bip16_active` must be computed **once** by the
/// caller (assemble_run header window) — no re-walk of headers and no rehash.
///
/// `wire`: when `Some`, script jobs share that Arc (no `Transaction` clone).
/// When `None` (unit-test connect), jobs own a deep clone of each non-cb tx.
pub(crate) fn assemble_block_prevouts(
    query: &Query,
    block: &Block,
    ctx: &ValidationContext<'_>,
    archived_tx_fks: Option<&[rbitcoin_primitives::Fk]>,
    pending_spent: &mut rbitcoin_query::OutPointSet,
    pending_creates: &mut PendingCreates,
    batch_parents: &rbitcoin_query::BatchParents,
    spend_edges: &rbitcoin_query::SpendEdges,
    create_txids: &[[u8; 32]],
    prev_mtp: u32,
    block_hash: &[u8; 32],
    bip16_active: bool,
    wire: Option<&Arc<Block>>,
    pres: Option<&Arc<[rbitcoin_query::TxPrecompute]>>,
) -> Result<
    (
        Vec<ScriptCheckJob>,
        Vec<(
            [u8; 32],
            u32,
            rbitcoin_primitives::Fk,
            rbitcoin_primitives::Fk,
            u32,
        )>,
        i64,
        Vec<u64>,
    ),
    ConsensusError,
> {
    assemble_prevout_guards(block, archived_tx_fks, create_txids)?;
    // Caller-supplied BIP16 must match hash+prev_mtp (no silent re-resolve).
    debug_assert_eq!(
        bip16_active,
        bip16_active_from_prev_mtp(ctx.params, ctx.height.0, block_hash, prev_mtp)
    );
    let flags = ScriptVerifyFlags::consensus_at(ctx, block_hash, bip16_active);

    let n_tx = block.txdata.len();
    let mut txid_index: TxidMap<usize> =
        TxidMap::with_capacity_and_hasher(n_tx, Default::default());
    for (i, id) in create_txids.iter().enumerate() {
        txid_index.insert(*id, i);
    }
    let mut acc = AsmPrevoutAcc::default();
    let mut clk_job = 0u64;
    let mut fees = 0i64;
    let mut tx_fees = vec![0u64; n_tx];
    let build_script_jobs =
        !crate::milestone::skips_on_query(ctx.milestone, query, ctx.height.0, block_hash);
    let mut script_jobs: Vec<ScriptCheckJob> = if build_script_jobs {
        Vec::with_capacity(n_tx.saturating_sub(1))
    } else {
        Vec::new()
    };
    let mut block_sigops_cost = match pres.and_then(|p| p.first()) {
        Some(p) => p.sigops.saturating_mul(4),
        None => legacy_sigop_count(&block.txdata[0]).saturating_mul(4),
    };
    let mut spends: Vec<(
        [u8; 32],
        u32,
        rbitcoin_primitives::Fk,
        rbitcoin_primitives::Fk,
        u32,
    )> = Vec::with_capacity(n_tx.saturating_mul(2));

    let t_loop = Instant::now();

    let lock_time_cutoff = assemble_lock_time_cutoff(ctx, block, prev_mtp);

    for (ti, tx) in block.txdata.iter().enumerate() {
        let spend_fk = archived_tx_fks.map(|fks| fks[ti]);
        let txid = create_txids[ti];

        if !is_final_tx(tx, ctx.height.0, lock_time_cutoff) {
            return Err(ConsensusError::BadTx("bad-txns-nonfinal"));
        }
        if tx.output.is_empty() {
            return Err(ConsensusError::BadTx("no outputs"));
        }
        if ti > 0 {
            tx_fees[ti] = assemble_non_cb_tx(
                ctx.params,
                block,
                tx,
                ti,
                txid,
                spend_fk,
                flags,
                bip16_active,
                wire,
                pres,
                &txid_index,
                pending_spent,
                pending_creates,
                batch_parents,
                spend_edges,
                &mut acc,
                &mut script_jobs,
                &mut spends,
                &mut fees,
                &mut block_sigops_cost,
                build_script_jobs,
                &mut clk_job,
            )?;
        }

        let create_fk = spend_fk.unwrap_or(rbitcoin_primitives::Fk::NULL);
        if !create_fk.is_null() {
            pending_creates.insert(txid, create_fk);
        }
    }

    let clk_prev = t_loop.elapsed().as_nanos() as u64;
    acc.flush(query.confirm_stats());
    rbitcoin_query::note_confirm(&query.confirm_stats().asm_prevout_ns, clk_prev);
    rbitcoin_query::note_confirm(&query.confirm_stats().asm_job_ns, clk_job);
    Ok((script_jobs, spends, fees, tx_fees))
}

fn assemble_prevout_guards(
    block: &Block,
    archived_tx_fks: Option<&[rbitcoin_primitives::Fk]>,
    create_txids: &[[u8; 32]],
) -> Result<(), ConsensusError> {
    if let Some(fks) = archived_tx_fks {
        if fks.len() != block.txdata.len() {
            return Err(ConsensusError::BadBlock("archived tx fk count mismatch"));
        }
    }
    if create_txids.len() != block.txdata.len() {
        return Err(ConsensusError::BadBlock(
            "invariant: create_txids length must match block.txdata (no assemble re-hash)",
        ));
    }
    if block.txdata.is_empty() {
        return Err(ConsensusError::BadBlock("empty block"));
    }
    if !block.txdata[0].is_coinbase() {
        return Err(ConsensusError::BadBlock("first tx not coinbase"));
    }
    Ok(())
}

fn assemble_lock_time_cutoff(ctx: &ValidationContext<'_>, block: &Block, prev_mtp: u32) -> u32 {
    // Height 0 has no MTP history, so the cutoff is the block time even
    // when CSV is active.
    if ctx.height.0 == 0 || !ctx.params.csv_active_at(ctx.height.0) {
        block.header.time
    } else {
        prev_mtp
    }
}

/// `MAX_BLOCK_SIGOPS_COST` (20_000 legacy sigops × witness scale 4).
#[inline]
fn exceeds_sigops_limit(cost: u64) -> bool {
    const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;
    cost > MAX_BLOCK_SIGOPS_COST
}

/// Attach the precompute slice only when `ti` is inside it.
#[inline]
fn should_use_pres(ti: usize, len: usize) -> bool {
    ti < len
}

/// Core `MAX_MONEY` (21_000_000 BTC). Structure validation uses this for
/// each output and for `TxPrecompute::out_sum`. The no-precompute value sum
/// uses it for each output too.
///
/// `Amount::MAX_MONEY` fits in `i64`, so a value this returns false for
/// cannot become negative when `money_range_out_sum` or
/// `assemble_tx_value_out` casts it.
#[inline]
fn exceeds_max_money(sats: u64) -> bool {
    sats > Amount::MAX_MONEY.to_sat()
}

/// Signed satoshis for an `out_sum` that already passed [`exceeds_max_money`].
#[inline]
fn money_range_out_sum(out_sum: u64) -> i64 {
    debug_assert!(
        !exceeds_max_money(out_sum),
        "out_sum above MAX_MONEY must be rejected in validate_block_structure_with_pres"
    );
    out_sum as i64
}

#[allow(clippy::too_many_arguments)]
fn assemble_non_cb_tx(
    params: &ChainParams,
    block: &Block,
    tx: &Transaction,
    ti: usize,
    txid: [u8; 32],
    spend_fk: Option<rbitcoin_primitives::Fk>,
    flags: ScriptVerifyFlags,
    bip16_active: bool,
    wire: Option<&Arc<Block>>,
    pres: Option<&Arc<[rbitcoin_query::TxPrecompute]>>,
    txid_index: &TxidMap<usize>,
    pending_spent: &mut rbitcoin_query::OutPointSet,
    pending_creates: &PendingCreates,
    batch_parents: &rbitcoin_query::BatchParents,
    spend_edges: &rbitcoin_query::SpendEdges,
    acc: &mut AsmPrevoutAcc,
    script_jobs: &mut Vec<ScriptCheckJob>,
    spends: &mut Vec<(
        [u8; 32],
        u32,
        rbitcoin_primitives::Fk,
        rbitcoin_primitives::Fk,
        u32,
    )>,
    fees: &mut i64,
    block_sigops_cost: &mut u64,
    build_script_jobs: bool,
    clk_job: &mut u64,
) -> Result<u64, ConsensusError> {
    if tx.input.is_empty() {
        return Err(ConsensusError::BadTx("no inputs"));
    }
    let (value_in, prevouts, tx_in_sigops) = assemble_non_cb_inputs(
        params,
        block,
        tx,
        ti,
        spend_fk,
        flags,
        bip16_active,
        txid_index,
        pending_spent,
        pending_creates,
        batch_parents,
        spend_edges,
        wire,
        acc,
        spends,
        build_script_jobs,
    )?;
    let tx_legacy_sigops = match pres.and_then(|p| p.get(ti)) {
        Some(p) => p.sigops.saturating_mul(4),
        None => legacy_sigop_count(tx).saturating_mul(4),
    };
    *block_sigops_cost = block_sigops_cost
        .checked_add(tx_legacy_sigops)
        .and_then(|c| c.checked_add(tx_in_sigops))
        .ok_or(ConsensusError::BadBlock("bad-blk-sigops"))?;
    if exceeds_sigops_limit(*block_sigops_cost) {
        return Err(ConsensusError::BadBlock("bad-blk-sigops"));
    }
    let value_out = assemble_tx_value_out(tx, ti, pres)?;
    if value_out > value_in {
        return Err(ConsensusError::BadTx("in < out"));
    }
    let fee = value_in
        .checked_sub(value_out)
        .ok_or(ConsensusError::BadTx("fee overflow"))?;
    let fee_sat = u64::try_from(fee).map_err(|_| ConsensusError::BadTx("fee overflow"))?;
    *fees = fees
        .checked_add(fee)
        .ok_or(ConsensusError::BadTx("fee overflow"))?;
    if build_script_jobs {
        let t_job = Instant::now();
        let mut job = match (wire, prevouts) {
            (Some(w), JobPrevouts::Shared(v)) => ScriptCheckJob::from_parts(
                txid,
                JobPrevouts::Shared(v),
                JobTx::shared(Arc::clone(w), ti),
                flags,
            ),
            (None, JobPrevouts::Owned(v)) => ScriptCheckJob::with_txid(txid, v, tx.clone(), flags),
            _ => {
                return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                    "invariant: script job prevouts",
                )));
            }
        };
        if let Some(ps) = pres {
            if should_use_pres(ti, ps.len()) {
                job = job.with_pre_slice(Arc::clone(ps), ti);
            }
        }
        script_jobs.push(job);
        *clk_job = clk_job.saturating_add(t_job.elapsed().as_nanos() as u64);
    }
    Ok(fee_sat)
}

fn assemble_tx_value_out(
    tx: &Transaction,
    ti: usize,
    pres: Option<&Arc<[rbitcoin_query::TxPrecompute]>>,
) -> Result<i64, ConsensusError> {
    match pres.and_then(|p| p.get(ti)) {
        Some(p) => Ok(money_range_out_sum(p.out_sum)),
        None => {
            let mut value_out = 0i64;
            for o in &tx.output {
                let sats_u = o.value.to_sat();
                if exceeds_max_money(sats_u) {
                    return Err(ConsensusError::BadBlock("bad-txns-vout-toolarge"));
                }
                value_out = value_out
                    .checked_add(sats_u as i64)
                    .ok_or(ConsensusError::BadTx("value out overflow"))?;
            }
            Ok(value_out)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn assemble_non_cb_inputs(
    params: &ChainParams,
    block: &Block,
    tx: &Transaction,
    ti: usize,
    spend_fk: Option<rbitcoin_primitives::Fk>,
    flags: ScriptVerifyFlags,
    bip16_active: bool,
    txid_index: &TxidMap<usize>,
    pending_spent: &mut rbitcoin_query::OutPointSet,
    pending_creates: &PendingCreates,
    batch_parents: &rbitcoin_query::BatchParents,
    spend_edges: &rbitcoin_query::SpendEdges,
    wire: Option<&Arc<Block>>,
    acc: &mut AsmPrevoutAcc,
    spends: &mut Vec<(
        [u8; 32],
        u32,
        rbitcoin_primitives::Fk,
        rbitcoin_primitives::Fk,
        u32,
    )>,
    build_script_jobs: bool,
) -> Result<(i64, JobPrevouts, u64), ConsensusError> {
    let mut value_in = 0i64;
    let mut prevouts = if build_script_jobs && wire.is_some() {
        JobPrevouts::Shared(Vec::with_capacity(tx.input.len()))
    } else {
        JobPrevouts::owned(Vec::with_capacity(if build_script_jobs {
            tx.input.len()
        } else {
            0
        }))
    };
    let edges = spend_fk.and_then(|fk| fk.get().and_then(|id| spend_edges.get(&id)));
    let mut tx_in_sigops = 0u64;
    for (ii, input) in tx.input.iter().enumerate() {
        let op = input.previous_output;
        let key = (op.txid.to_byte_array(), op.vout);
        // The genesis coinbase stays indexed for RPC and Electrum, but it is
        // not a coin (Core `ConnectBlock` genesis early return).
        if params.is_genesis_coinbase(&key.0) {
            return Err(ConsensusError::MissingPrevout);
        }
        if !pending_spent.insert(key) {
            return Err(ConsensusError::BadTx("double spend in block"));
        }
        if let Some(&pj) = txid_index.get(&key.0) {
            if pj >= ti {
                return Err(ConsensusError::MissingPrevout);
            }
            if pj == 0 {
                return Err(ConsensusError::BadTx("coinbase immature"));
            }
        }
        let prev_fk = edges
            .as_ref()
            .and_then(|t| t.get(ii))
            .and_then(|e| e.create_fk.get().map(|_| e.create_fk))
            .or_else(|| pending_creates.get(&key.0).copied());
        let prev_out = resolve_prevout(
            block,
            op,
            input,
            prev_fk,
            txid_index,
            ti,
            batch_parents,
            bip16_active,
            flags.witness_active,
            build_script_jobs,
            wire,
            acc,
        )?;
        let create_fk = prev_out.create_fk;
        tx_in_sigops = tx_in_sigops.saturating_add(prev_out.input_sigops);
        spends.push((
            key.0,
            key.1,
            spend_fk.unwrap_or(rbitcoin_primitives::Fk::NULL),
            create_fk,
            ii as u32,
        ));
        value_in = value_in
            .checked_add(prev_out.txout.value.to_sat() as i64)
            .ok_or(ConsensusError::BadTx("value in overflow"))?;
        if build_script_jobs {
            match &mut prevouts {
                JobPrevouts::Shared(v) => {
                    let shared = prev_out.shared.ok_or(ConsensusError::Store(
                        rbitcoin_store::StoreError::Corrupt(
                            "invariant: wire confirm prevout shares script bytes",
                        ),
                    ))?;
                    v.push(shared);
                }
                JobPrevouts::Owned(v) => v.push(prev_out.txout),
            }
        }
    }
    Ok((value_in, prevouts, tx_in_sigops))
}

fn check_coinbase_subsidy(
    block: &Block,
    ctx: &ValidationContext<'_>,
    fees: i64,
) -> Result<(), ConsensusError> {
    let subsidy = block_subsidy(ctx.height.0, ctx.params);
    let mut coinbase_out = 0i64;
    for o in &block.txdata[0].output {
        coinbase_out = coinbase_out
            .checked_add(o.value.to_sat() as i64)
            .ok_or(ConsensusError::BadBlock("coinbase value overflow"))?;
    }
    let max_cb = subsidy
        .checked_add(fees)
        .ok_or(ConsensusError::BadBlock("subsidy+fees overflow"))?;
    if coinbase_out > max_cb {
        return Err(ConsensusError::BadBlock("coinbase excess value"));
    }
    Ok(())
}

/// Local wall times for one block's structural pass (write path diagnostics).
///
/// Measured with `Instant` — **not** deltas of window atomics (those race with
/// `sample_and_reset` mid-batch and produced false `spent=0` on slow writes).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct StructuralPhaseNs {
    pub spent_ns: u64,
    /// Pin abs collect + bulk on-disk 8-byte spender meta pread.
    pub spent_abs_ns: u64,
    /// `is_confirmed_strong_at` on non-null fields (still durable authority).
    pub spent_strong_ns: u64,
    /// Cold unspent_create_vouts / null-create probes.
    pub spent_cold_ns: u64,
    /// pending_spent order gate (CPU).
    pub spent_pending_ns: u64,
    pub create_h_ns: u64,
    pub bip68_ns: u64,
}

/// Post-script structural checks: durable spentness, maturity, BIP68, coinbase subsidy.
///
/// Runs in height order on the write path (after scripts). `pending_spent` is
/// write-local across a multi-height run.
///
/// **BIP68** create-height lives here (not optimistic load assemble) so confirm
/// load does not walk create height for every parent. Heights: bulk fence.
/// Coin MTP only for time-type relative locks on version ≥2 txs (v1 skipped).
///
/// Write-path spend annotate slots: abs edge plus the meta structural already read.
///
/// Filled during spentness and passed to annotate. No second edge copy.
#[derive(Clone, Debug, Default)]
pub(crate) struct AnnotateSlots {
    pub abs_edges: Vec<(
        u64,
        rbitcoin_primitives::Fk,
        u32,
        rbitcoin_primitives::Fk,
        u32,
    )>,
    pub known: Vec<(rbitcoin_primitives::Fk, u8, u32)>,
}

impl AnnotateSlots {
    pub(crate) fn push(
        &mut self,
        edge: (
            u64,
            rbitcoin_primitives::Fk,
            u32,
            rbitcoin_primitives::Fk,
            u32,
        ),
        known: (rbitcoin_primitives::Fk, u8, u32),
    ) {
        self.abs_edges.push(edge);
        self.known.push(known);
    }
}

/// Per-block spentness scratch. Capacity stays across blocks in one write batch.
/// [`AnnotateSlots`] accumulate for the whole batch.
pub(crate) struct StructuralScratch {
    abs_jobs: Vec<StructuralAbsJob>,
    abs_seen: rbitcoin_query::U64Set,
    unique_fks: Vec<rbitcoin_primitives::Fk>,
    height_by_id: U64Map<u32>,
    skip_n: std::collections::HashMap<
        (u64, u32),
        u32,
        BuildHasherDefault<rbitcoin_query::OutPointHasher>,
    >,
    skip: OverlayMetaSkip,
    disk_jobs: Vec<StructuralAbsJob>,
    abs_offs: Vec<u64>,
    field_fks: Vec<rbitcoin_primitives::Fk>,
    field_seen: rbitcoin_query::U64Set,
    field_h_by_id: U64Map<u32>,
    durable_spent: DurableSpentSet,
    height_list: Vec<u32>,
    create_height_by_fk: FkMap<u32>,
    pub slots: AnnotateSlots,
}

impl Default for StructuralScratch {
    fn default() -> Self {
        Self {
            abs_jobs: Vec::new(),
            abs_seen: rbitcoin_query::U64Set::default(),
            unique_fks: Vec::new(),
            height_by_id: U64Map::default(),
            skip_n: std::collections::HashMap::with_hasher(Default::default()),
            skip: OverlayMetaSkip::with_hasher(Default::default()),
            disk_jobs: Vec::new(),
            abs_offs: Vec::new(),
            field_fks: Vec::new(),
            field_seen: rbitcoin_query::U64Set::default(),
            field_h_by_id: U64Map::default(),
            durable_spent: DurableSpentSet::with_hasher(Default::default()),
            height_list: Vec::new(),
            create_height_by_fk: FkMap::default(),
            slots: AnnotateSlots::default(),
        }
    }
}

impl StructuralScratch {
    /// Drop annotate slots from the previous write batch. Per-block buffers
    /// stay for [`Self::begin_block`]; slots accumulate inside one batch.
    pub(crate) fn begin_batch(&mut self) {
        self.slots.abs_edges.clear();
        self.slots.known.clear();
    }

    fn begin_block(&mut self) {
        self.abs_jobs.clear();
        self.abs_seen.clear();
        self.unique_fks.clear();
        self.height_by_id.clear();
        self.skip_n.clear();
        self.skip.clear();
        self.disk_jobs.clear();
        self.abs_offs.clear();
        self.field_fks.clear();
        self.field_seen.clear();
        self.field_h_by_id.clear();
        self.durable_spent.clear();
        self.height_list.clear();
        self.create_height_by_fk.clear();
    }
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
/// **Spentness:** pin denserels → abs + bulk 8-byte meta. Sparse durable-**spent**
/// set (not unspent). Missing abs / short meta is hard `Err`. **Multi-list** after
/// reorg annotate is a protocol cold walk (`has_confirmed_strong_spender_create`)
/// — not a hard fail (tip-follow reorgs leave multi flags by design). Emits
/// Annotate slots on `scratch` for pure-write annotate.
pub(crate) fn structural_validate_spends(
    query: &Query,
    block: &Block,
    ctx: &ValidationContext<'_>,
    archived_tx_fks: Option<&[rbitcoin_primitives::Fk]>,
    spends: &[(
        [u8; 32],
        u32,
        rbitcoin_primitives::Fk,
        rbitcoin_primitives::Fk,
        u32,
    )],
    fees: i64,
    pending_spent: &mut rbitcoin_query::OutPointSet,
    batch_parents: &rbitcoin_query::BatchParents,
    mtp_cache: &mut U32Map<u32>,
    run_create_height: &RunCreateHeight,
    class_a_wave: &ClassAWave,
    scratch: &mut StructuralScratch,
    precomputed_abs: Option<&[StructuralAbsJob]>,
) -> Result<StructuralPhaseNs, ConsensusError> {
    use std::time::Instant;

    scratch.begin_block();
    let maturity = ctx.params.coinbase_maturity();
    // BIP30's txid batch is inside `spent_ns` (signet runs it on every block).
    let t_spent = Instant::now();
    reject_bip30_unspent_overwrite(query, block, ctx)?;
    let t_abs = Instant::now();
    structural_abs_heights(
        query,
        spends,
        batch_parents,
        run_create_height,
        scratch,
        precomputed_abs,
    )?;
    let tip = query.tip_height().map(|h| h.0);
    let mut spent_strong_ns = 0u64;
    let mut multi_list_ns = 0u64;
    if !scratch.abs_jobs.is_empty() {
        fill_overlay_skip(spends, class_a_wave, scratch);
        let loaded = structural_load_durable_spent(query, tip, scratch)?;
        multi_list_ns = loaded.0;
        spent_strong_ns = loaded.1;
    }
    let spent_abs_ns = (t_abs.elapsed().as_nanos() as u64).saturating_sub(spent_strong_ns);
    let spent_cold_ns = multi_list_ns;
    let t_pending = Instant::now();
    structural_mark_pending(spends, pending_spent, &scratch.durable_spent)?;
    let spent_pending_ns = t_pending.elapsed().as_nanos() as u64;
    let spent_ns = t_spent.elapsed().as_nanos() as u64;
    let t_create = Instant::now();
    structural_create_heights(
        query,
        batch_parents,
        run_create_height,
        ctx.height.0,
        maturity,
        scratch,
    )?;
    let create_h_ns = t_create.elapsed().as_nanos() as u64;
    let t_bip68 = Instant::now();
    structural_bip68(
        query,
        block,
        ctx,
        spends,
        &scratch.create_height_by_fk,
        mtp_cache,
    )?;
    let bip68_ns = t_bip68.elapsed().as_nanos() as u64;
    let _ = archived_tx_fks;
    check_coinbase_subsidy(block, ctx, fees)?;
    Ok(StructuralPhaseNs {
        spent_ns,
        spent_abs_ns,
        spent_strong_ns,
        spent_cold_ns,
        spent_pending_ns,
        create_h_ns,
        bip68_ns,
    })
}

pub(crate) type StructuralAbsJob = (u64, u32, u64, rbitcoin_primitives::Fk, u32);

/// Creates this write batch's Class A append committed.
///
/// Only these spent slots carry the same-batch sole-spender overlay. A run
/// create archived by an earlier wave has whatever that wave and later
/// annotates left on disk, so structural reads and annotates it.
#[derive(Default)]
pub(crate) struct ClassAWave(Vec<rbitcoin_primitives::Fk>);

impl ClassAWave {
    pub(crate) fn new(mut fks: Vec<rbitcoin_primitives::Fk>) -> Self {
        fks.sort_unstable_by_key(|f| f.0);
        Self(fks)
    }

    fn contains(&self, fk: rbitcoin_primitives::Fk) -> bool {
        self.0.binary_search_by_key(&fk.0, |f| f.0).is_ok()
    }
}

/// Create heights for one write batch.
///
/// Contiguous per-block fk spans are the IBD shape (`first` + count). A gap
/// or overlap uses the map so a fk between spans does not inherit a height.
/// Each block's first fk is its coinbase: a span's `first`, or the map's flag.
pub(crate) enum RunCreateHeight {
    Spans(Vec<(u64, u64, u32)>),
    Map(FkMap<(u32, bool)>),
}

impl RunCreateHeight {
    pub(crate) fn from_blocks<'a>(
        blocks: impl IntoIterator<Item = (u32, &'a [rbitcoin_primitives::Fk])>,
    ) -> Self {
        let blocks: Vec<(u32, &'a [rbitcoin_primitives::Fk])> = blocks.into_iter().collect();
        if let Some(spans) = contiguous_create_spans(&blocks) {
            Self::Spans(spans)
        } else {
            let mut map = FkMap::default();
            for (height, fks) in blocks {
                for (i, fk) in fks.iter().enumerate() {
                    map.insert(*fk, (height, i == 0));
                }
            }
            Self::Map(map)
        }
    }

    pub(crate) fn get(&self, fk: rbitcoin_primitives::Fk) -> Option<u32> {
        self.create(fk).map(|(height, _)| height)
    }

    /// Height of a create in this batch and whether it is its block's coinbase.
    pub(crate) fn create(&self, fk: rbitcoin_primitives::Fk) -> Option<(u32, bool)> {
        match self {
            Self::Map(map) => map.get(&fk).copied(),
            Self::Spans(spans) => {
                let id = fk.get()?;
                let i = spans.partition_point(|span| span.0 <= id);
                let (first, end, height) = spans.get(i.checked_sub(1)?)?;
                (*end > id).then_some((*height, *first == id))
            }
        }
    }
}

/// `Some` when every non-empty block is `[first, first+n)` and spans do not overlap.
///
/// A null fk, a gap, or an id that would wrap is `None` so the caller uses the map.
/// A wrapped end must not cover fks that are not in the block.
fn contiguous_create_spans(
    blocks: &[(u32, &[rbitcoin_primitives::Fk])],
) -> Option<Vec<(u64, u64, u32)>> {
    let mut spans = Vec::with_capacity(blocks.len());
    for &(height, fks) in blocks {
        if fks.is_empty() {
            continue;
        }
        let mut ids = fks.iter().map(|fk| fk.get());
        let first = ids.next().flatten()?;
        let mut prev = first;
        for id in ids {
            let id = id?;
            let next = prev.checked_add(1)?;
            if id != next {
                return None;
            }
            prev = id;
        }
        let end = prev.checked_add(1)?;
        spans.push((first, end, height));
    }
    spans.sort_unstable_by_key(|span| span.0);
    for pair in spans.windows(2) {
        if pair[0].1 > pair[1].0 {
            return None;
        }
    }
    Some(spans)
}
type DurableSpentSet =
    std::collections::HashSet<(u64, u32), BuildHasherDefault<rbitcoin_query::OutPointHasher>>;
type OverlayMetaSkip = std::collections::HashMap<
    (u64, u32),
    (rbitcoin_primitives::Fk, u32),
    BuildHasherDefault<rbitcoin_query::OutPointHasher>,
>;

fn fill_overlay_skip(
    spends: &[(
        [u8; 32],
        u32,
        rbitcoin_primitives::Fk,
        rbitcoin_primitives::Fk,
        u32,
    )],
    class_a_wave: &ClassAWave,
    scratch: &mut StructuralScratch,
) {
    for &(_, vout, sfk, cfk, vin) in spends {
        if !class_a_wave.contains(cfk) {
            continue;
        }
        let Some(id) = cfk.get() else {
            continue;
        };
        let key = (id, vout);
        *scratch.skip_n.entry(key).or_insert(0) += 1;
        scratch.skip.entry(key).or_insert((sfk, vin));
    }
    let skip_n = &scratch.skip_n;
    scratch
        .skip
        .retain(|k, _| skip_n.get(k).copied() == Some(1));
}

fn overlay_meta_is_skip(
    id: u64,
    vout: u32,
    sfk: rbitcoin_primitives::Fk,
    vin: u32,
    skip: &OverlayMetaSkip,
) -> bool {
    skip.get(&(id, vout)) == Some(&(sfk, vin))
}

fn structural_abs_heights(
    query: &Query,
    spends: &[(
        [u8; 32],
        u32,
        rbitcoin_primitives::Fk,
        rbitcoin_primitives::Fk,
        u32,
    )],
    batch_parents: &rbitcoin_query::BatchParents,
    run_create_height: &RunCreateHeight,
    scratch: &mut StructuralScratch,
    precomputed_abs: Option<&[StructuralAbsJob]>,
) -> Result<(), ConsensusError> {
    if let Some(jobs) = precomputed_abs {
        // Tests recompute so a stale list cannot skip a missing abs.
        #[cfg(test)]
        {
            let fresh = batch_parents
                .spend_abs_jobs(
                    spends
                        .iter()
                        .map(|&(_, vout, sfk, cfk, vin)| (cfk, vout, sfk, vin)),
                )
                .map_err(ConsensusError::from)?;
            if fresh.as_slice() != jobs {
                return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                    "invariant: precomputed spend abs diverged from pin",
                )));
            }
        }
        scratch.abs_jobs.extend_from_slice(jobs);
    } else {
        batch_parents
            .spend_abs_jobs_into(
                spends
                    .iter()
                    .map(|&(_, vout, sfk, cfk, vin)| (cfk, vout, sfk, vin)),
                &mut scratch.abs_jobs,
                &mut scratch.abs_seen,
            )
            .map_err(ConsensusError::from)?;
    }
    scratch.unique_fks.extend(
        scratch
            .abs_jobs
            .iter()
            .map(|(id, _, _, _, _)| rbitcoin_primitives::Fk(*id)),
    );
    scratch.unique_fks.sort_unstable_by_key(|f| f.0);
    scratch.unique_fks.dedup();
    let durable_heights = query
        .store()
        .tx_height_get_batch(&scratch.unique_fks)
        .map_err(ConsensusError::from)?;
    for (fk, h) in scratch.unique_fks.iter().zip(durable_heights) {
        let Some(id) = fk.get() else {
            continue;
        };
        let Some(h) = h.or_else(|| run_create_height.get(*fk)) else {
            continue;
        };
        scratch.height_by_id.insert(id, h);
    }
    Ok(())
}

fn structural_load_durable_spent(
    query: &Query,
    tip: Option<u32>,
    scratch: &mut StructuralScratch,
) -> Result<(u64, u64), ConsensusError> {
    use std::time::Instant;
    let mut ovl_n = 0u64;
    for &job in &scratch.abs_jobs {
        let (id, vout, abs, sfk, vin) = job;
        if overlay_meta_is_skip(id, vout, sfk, vin, &scratch.skip) {
            ovl_n = ovl_n.saturating_add(1);
            continue;
        }
        scratch.disk_jobs.push(job);
        scratch.abs_offs.push(abs);
    }
    rbitcoin_query::note_confirm(&query.confirm_stats().spend_overlay_skip_n, ovl_n);
    if scratch.abs_offs.is_empty() {
        return Ok((0, 0));
    }
    let meta_backend = rbitcoin_store::spend_meta_backend();
    let t_meta = Instant::now();
    let metas = query
        .store()
        .get_spender_meta_at_abs_batch_backend(&scratch.abs_offs, meta_backend)
        .map_err(ConsensusError::from)?;
    let meta_ns = t_meta.elapsed().as_nanos() as u64;
    rbitcoin_query::note_confirm(&query.confirm_stats().spend_meta_ns, meta_ns);
    rbitcoin_query::note_confirm(
        &query.confirm_stats().spend_meta_n,
        scratch.abs_offs.len() as u64,
    );
    let _ = meta_backend;
    if metas.len() != scratch.disk_jobs.len() {
        return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
            "invariant: structural meta batch length",
        )));
    }
    let t_strong = Instant::now();
    for row in &metas {
        let Some((field, _, _)) = row else {
            continue;
        };
        if field.is_null() {
            continue;
        }
        if let Some(fid) = field.get() {
            if scratch.field_seen.insert(fid) {
                scratch.field_fks.push(*field);
            }
        }
    }
    let field_heights = query
        .store()
        .tx_height_get_batch(&scratch.field_fks)
        .map_err(ConsensusError::from)?;
    for (fk, h) in scratch.field_fks.iter().zip(field_heights) {
        if let Some((id, h)) = fk.get().zip(h) {
            scratch.field_h_by_id.insert(id, h);
        }
    }
    let jobs = std::mem::take(&mut scratch.disk_jobs);
    let applied = jobs
        .iter()
        .copied()
        .zip(metas)
        .try_fold(0u64, |acc, (job, meta)| {
            let (id, vout, abs, sfk, vin) = job;
            let ns = structural_apply_one_meta(query, meta, id, vout, abs, sfk, vin, tip, scratch)?;
            Ok::<u64, ConsensusError>(acc.saturating_add(ns))
        });
    scratch.disk_jobs = jobs;
    let multi_list_ns = applied?;
    let spent_strong_ns = t_strong
        .elapsed()
        .as_nanos()
        .saturating_sub(multi_list_ns as u128) as u64;
    Ok((multi_list_ns, spent_strong_ns))
}

#[allow(clippy::too_many_arguments)]
fn structural_apply_one_meta(
    query: &Query,
    meta: Option<(rbitcoin_primitives::Fk, u8, u32)>,
    id: u64,
    vout: u32,
    abs: u64,
    sfk: rbitcoin_primitives::Fk,
    vin: u32,
    tip: Option<u32>,
    scratch: &mut StructuralScratch,
) -> Result<u64, ConsensusError> {
    use std::time::Instant;
    let Some((field, flags, field_vin)) = meta else {
        return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
            "invariant: structural spender meta short/OOB (cold forbidden)",
        )));
    };
    scratch.slots.push(
        (abs, rbitcoin_primitives::Fk(id), vout, sfk, vin),
        (field, flags, field_vin),
    );
    let multi = flags & rbitcoin_store::output_flags::MULTI_SPENDER != 0;
    if multi {
        let t_m = Instant::now();
        let spent = query
            .store()
            .has_confirmed_strong_spender_create(rbitcoin_primitives::Fk(id), vout, None)
            .map_err(ConsensusError::from)?;
        let ns = t_m.elapsed().as_nanos() as u64;
        if spent {
            scratch.durable_spent.insert((id, vout));
        }
        return Ok(ns);
    }
    if field.is_null() {
        return Ok(0);
    }
    let strong = query
        .store()
        .is_confirmed_strong_at(field, tip)
        .map_err(ConsensusError::from)?;
    if !strong {
        return Ok(0);
    }
    let create_h = scratch.height_by_id.get(&id).copied();
    let spend_h = field
        .get()
        .and_then(|fid| scratch.field_h_by_id.get(&fid).copied());
    if let (Some(ch), Some(sh)) = (create_h, spend_h) {
        if sh < ch {
            return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                "invariant: confirmed spender below its create height",
            )));
        }
    }
    scratch.durable_spent.insert((id, vout));
    Ok(0)
}

fn structural_mark_pending(
    spends: &[(
        [u8; 32],
        u32,
        rbitcoin_primitives::Fk,
        rbitcoin_primitives::Fk,
        u32,
    )],
    pending_spent: &mut rbitcoin_query::OutPointSet,
    durable_spent: &DurableSpentSet,
) -> Result<(), ConsensusError> {
    for &(prev_txid, vout, _spend_fk, create_fk, _vin) in spends {
        let key = (prev_txid, vout);
        let spent = if create_fk.is_null() {
            false
        } else if let Some(id) = create_fk.get() {
            durable_spent.contains(&(id, vout))
        } else {
            false
        };
        if spent || !pending_spent.insert(key) {
            return Err(ConsensusError::PrevoutSpent);
        }
    }
    Ok(())
}

fn structural_create_heights(
    query: &Query,
    batch_parents: &rbitcoin_query::BatchParents,
    run_create_height: &RunCreateHeight,
    spend_height: u32,
    maturity: u32,
    scratch: &mut StructuralScratch,
) -> Result<(), ConsensusError> {
    // `confirmed[h]` for a height in this batch is written at Class C, after
    // structural; the batch index owns coinbase identity there.
    scratch.height_list.extend(
        scratch
            .height_by_id
            .iter()
            .filter(|&(&id, &h)| run_create_height.get(rbitcoin_primitives::Fk(id)) != Some(h))
            .map(|(_, &h)| h),
    );
    scratch.height_list.sort_unstable();
    scratch.height_list.dedup();
    let coinbase_fk_by_height = query
        .store()
        .coinbase_fk_at_heights(&scratch.height_list)
        .map_err(ConsensusError::from)?;
    let n_unique = scratch.unique_fks.len();
    for i in 0..n_unique {
        let create_fk = scratch.unique_fks[i];
        let Some(id) = create_fk.get() else {
            continue;
        };
        let Some(&durable_h) = scratch.height_by_id.get(&id) else {
            return Err(ConsensusError::BadTx("bad-txns-inputs-missingorspent"));
        };
        // Core connects a run one block at a time: a create from a later
        // block of this batch is not yet a coin when this block spends it.
        if durable_h > spend_height {
            return Err(ConsensusError::MissingPrevout);
        }
        let pin_cb = batch_parents.get_parent_coinbase(create_fk);
        let is_cb = match (pin_cb, run_create_height.create(create_fk)) {
            (Some(cb), _) => cb,
            (None, Some((h, cb))) if h == durable_h => cb,
            (None, _) => {
                let cb = coinbase_fk_by_height
                    .get(&durable_h)
                    .ok_or(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                        "invariant: no coinbase fk at confirmed create height",
                    )))?;
                *cb == create_fk
            }
        };
        if is_cb && spend_height < durable_h.saturating_add(maturity) {
            return Err(ConsensusError::BadTx("coinbase immature"));
        }
        scratch.create_height_by_fk.insert(create_fk, durable_h);
    }
    Ok(())
}

fn structural_bip68(
    query: &Query,
    block: &Block,
    ctx: &ValidationContext<'_>,
    spends: &[(
        [u8; 32],
        u32,
        rbitcoin_primitives::Fk,
        rbitcoin_primitives::Fk,
        u32,
    )],
    create_height_by_fk: &FkMap<u32>,
    mtp_cache: &mut U32Map<u32>,
) -> Result<(), ConsensusError> {
    if !ctx.params.csv_active_at(ctx.height.0) {
        return Ok(());
    }
    const DISABLE: u32 = 1 << 31;
    const TYPE_FLAG: u32 = 1 << 22;
    let prev_mtp = if ctx.height.0 == 0 {
        0
    } else {
        mtp_at(query, Height(ctx.height.0 - 1), mtp_cache)?
    };
    let mut si = 0usize;
    let mut prev_heights: Vec<u32> = Vec::new();
    let mut coin_mtps: Vec<u32> = Vec::new();
    for tx in block.txdata.iter().skip(1) {
        let n_in = tx.input.len();
        if si + n_in > spends.len() {
            return Err(ConsensusError::BadBlock(
                "structural spends/tx input mismatch",
            ));
        }
        let tx_spends = &spends[si..si + n_in];
        si += n_in;
        if !bip68_active_for_tx(tx) {
            continue;
        }
        prev_heights.clear();
        coin_mtps.clear();
        prev_heights.reserve(n_in);
        coin_mtps.reserve(n_in);
        for (inp, &(_ptid, _vout, _sfk, create_fk, _vin)) in tx.input.iter().zip(tx_spends.iter()) {
            let ch = if create_fk.is_null() {
                ctx.height.0
            } else {
                match create_height_by_fk.get(&create_fk) {
                    Some(&h) => h,
                    None => return Err(ConsensusError::BadTx("bad-txns-nonfinal")),
                }
            };
            prev_heights.push(ch);
            let seq = inp.sequence.to_consensus_u32();
            let need_mtp = seq & DISABLE == 0 && seq & TYPE_FLAG != 0;
            // Height 0 is the genesis coin: one median lookup of block 0.
            // A missing create height is not height 0.
            let mtp = if !need_mtp {
                0
            } else {
                mtp_at(query, Height(ch.saturating_sub(1)), mtp_cache)?
            };
            coin_mtps.push(mtp);
        }
        if !sequence_locks_satisfied(tx, &prev_heights, &coin_mtps, ctx.height.0, prev_mtp) {
            return Err(ConsensusError::BadTx("bad-txns-nonfinal"));
        }
    }
    if si != spends.len() {
        return Err(ConsensusError::BadBlock(
            "structural spends/tx input mismatch",
        ));
    }
    Ok(())
}

/// MTP for write structural. Prefers assemble-carried `prev_mtp` (seeded into
/// `cache`). Misses go to durable headers only — never `get_header_plan`.
/// BIP30: a connected instance with any unspent spendable output may not be
/// overwritten.
/// Skipped for the two mainnet repeats, and when the header at BIP34 height
/// is this network's BIP34 hash and the block is below
/// [`crate::params::BIP34_IMPLIES_BIP30_LIMIT`]. Signet and regtest have no
/// BIP34 hash, so every block is checked. Just-archived self is unconnected.
fn reject_bip30_unspent_overwrite(
    query: &Query,
    block: &Block,
    ctx: &ValidationContext<'_>,
) -> Result<(), ConsensusError> {
    if ctx.params.is_bip30_repeat(ctx.height.0, block.block_hash())
        || bip34_ancestry_skips_bip30(query, ctx)
    {
        return Ok(());
    }
    let create_txids: Vec<[u8; 32]> = block
        .txdata
        .iter()
        .map(|tx| tx.compute_txid().to_byte_array())
        .collect();
    let hits = query
        .store()
        .get_fk_by_txid_batch(&create_txids)
        .map_err(ConsensusError::from)?;
    for (_txid, row) in hits {
        let Some((old_fk, _)) = row else {
            continue;
        };
        // Connected instance at *this* height is ourselves (re-validate /
        // already-confirmed fixture). BIP30 is an earlier unspent sibling.
        if query
            .store()
            .tx_height_get(old_fk)
            .map_err(ConsensusError::from)?
            == Some(ctx.height.0)
        {
            continue;
        }
        let (_, outs) = query
            .store()
            .get_tx_meta_and_outputs(old_fk)
            .map_err(ConsensusError::from)?;
        let mut unspent = false;
        for (v, out) in (0u32..).zip(&outs) {
            // Core's AddCoins never stores an unspendable output, so it is
            // not a coin that the overwrite could clobber.
            if crate::policy::is_unspendable(&out.script) {
                continue;
            }
            let spent = query
                .store()
                .has_confirmed_strong_spender_create(old_fk, v, None)
                .map_err(ConsensusError::from)?;
            if !spent {
                unspent = true;
                break;
            }
        }
        if unspent {
            return Err(ConsensusError::BadTx("bad-txns-BIP30"));
        }
    }
    Ok(())
}

fn bip34_ancestry_skips_bip30(query: &Query, ctx: &ValidationContext<'_>) -> bool {
    let height = ctx.height.0;
    if ctx.params.bip34_hash.is_none() {
        return false;
    }
    if height <= ctx.params.btc.bip34_height {
        return false;
    }
    let ancestor = query
        .header_at_height(Height(ctx.params.btc.bip34_height))
        .ok()
        .flatten()
        .map(|(_, rec)| bitcoin::BlockHash::from_byte_array(rec.hash));
    ctx.params
        .bip30_skipped_for_bip34_ancestry(height, ancestor)
}

fn mtp_at(query: &Query, height: Height, cache: &mut U32Map<u32>) -> Result<u32, ConsensusError> {
    if let Some(&t) = cache.get(&height.0) {
        return Ok(t);
    }
    let t = crate::header::median_time_past_store(query, height)?;
    cache.insert(height.0, t);
    Ok(t)
}

/// Whether this job can skip `verify_job_all_inputs`.
///
/// OP_TRUE scriptPubKey alone is **not** sufficient: scriptSig still runs
/// (CLTV/CSV may live there). Only skip when every input is a pure ACS spend
/// (empty scriptSig + empty witness + OP_TRUE spk).
#[inline]
fn job_needs_script_check(job: &ScriptCheckJob) -> bool {
    let tx: &bitcoin::Transaction = &job.tx;
    for i in 0..job.prevouts.len() {
        let Ok(spk) = job.prevout_script(i) else {
            return true;
        };
        if !is_anyone_can_spend(Script::from_bytes(spk)) {
            return true;
        }
        let Some(vin) = tx.input.get(i) else {
            return true;
        };
        if !vin.script_sig.is_empty() || !vin.witness.is_empty() {
            return true;
        }
    }
    false
}

#[inline]
pub(crate) fn verify_one_script_job(job: &ScriptCheckJob) -> Result<(), ConsensusError> {
    if job_needs_script_check(job) {
        crate::script::verify_job_all_inputs(job)
    } else {
        Ok(())
    }
}

/// Halving subsidy. Regtest interval is 150; other networks 210_000 (Core).
pub fn block_subsidy(height: u32, params: &ChainParams) -> i64 {
    let interval = params.subsidy_halving_interval();
    let halvings = height / interval;
    if halvings >= 64 {
        return 0;
    }
    50_0000_0000i64 >> halvings
}

struct ResolvedPrevout {
    txout: TxOut,
    /// Set when the script bytes stay in a block or pin `Arc`.
    shared: Option<rbitcoin_query::SharedPrevoutScript>,
    /// P2SH+witness sigop cost for this input's prevout script (not legacy).
    input_sigops: u64,
    /// Class A create fk for this prevout (or `NULL` for same-block). Load pin
    /// denserels must carry identity matching wire `prev_txid` for this fk.
    create_fk: rbitcoin_primitives::Fk,
}

/// BIP65/113 nLockTime threshold: values below are block heights, above are unix times.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// Absolute locktime vs block height / time cutoff.
///
/// `lock_time_cutoff` is the comparison time: **MTP of the previous block** after
/// BIP113 (CSV package), else the block header timestamp.
pub fn is_final_tx(tx: &Transaction, block_height: u32, lock_time_cutoff: u32) -> bool {
    let lt = tx.lock_time.to_consensus_u32();
    if lt == 0 {
        return true;
    }
    if lt < LOCKTIME_THRESHOLD {
        if lt < block_height {
            return true;
        }
    } else if lt < lock_time_cutoff {
        return true;
    }
    tx.input.iter().all(|i| i.sequence.is_final())
}

/// BIP68 / CSV version gate: Core compares `nVersion` as **unsigned**
/// (`uint32_t >= 2`). rust-bitcoin exposes `Version(i32)`; cast explicitly so
/// `0xFFFFFFFF` enforces locks (not signed `-1 < 2`).
/// See **RB-001** in `docs/rust-bitcoin-limitations.md` and
/// `docs/external_findings/003-bip68-version-signedness-consensus-split.md`.
#[inline]
pub fn bip68_active_for_tx(tx: &Transaction) -> bool {
    (tx.version.0 as u32) >= 2
}

/// BIP68 relative locks when `tx.version` as u32 ≥ 2.
///
/// `prev_heights[i]` / `prev_mtps[i]`: create height and MTP of the block *before*
/// the creating block. Height 0 is the genesis coin; its median is that
/// block's timestamp, not 0. A missing height slice or a zero median fails closed.
/// `block_height` = containing block; `block_prev_mtp` = MTP of previous block.
pub fn sequence_locks_satisfied(
    tx: &Transaction,
    prev_heights: &[u32],
    prev_coin_mtps: &[u32],
    block_height: u32,
    block_prev_mtp: u32,
) -> bool {
    if !bip68_active_for_tx(tx) {
        return true;
    }
    const DISABLE: u32 = 1 << 31;
    const TYPE_FLAG: u32 = 1 << 22;
    const MASK: u32 = 0x0000_ffff;
    const GRANULARITY: u32 = 9;

    let mut min_height: i64 = -1;
    let mut min_time: i64 = -1;
    for (i, inp) in tx.input.iter().enumerate() {
        let seq = inp.sequence.to_consensus_u32();
        if seq & DISABLE != 0 {
            continue;
        }
        // A missing height slice is unresolved. Height 0 is the genesis coin.
        // raw_mtp 0 is unresolved: it is not a real median.
        let Some(&coin_h) = prev_heights.get(i) else {
            return false;
        };
        let rel = (seq & MASK) as i64;
        if seq & TYPE_FLAG != 0 {
            let Some(&raw_mtp) = prev_coin_mtps.get(i) else {
                return false;
            };
            if raw_mtp == 0 {
                return false;
            }
            min_time = min_time.max(i64::from(raw_mtp) + (rel << GRANULARITY) - 1);
        } else {
            min_height = min_height.max(i64::from(coin_h) + rel - 1);
        }
    }
    // Core EvaluateSequenceLocks: fail if minHeight >= block.nHeight or minTime >= prev MTP.
    if min_height >= i64::from(block_height) {
        return false;
    }
    if min_time >= i64::from(block_prev_mtp) {
        return false;
    }
    true
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
fn resolve_prevout(
    block: &Block,
    op: OutPoint,
    inp: &bitcoin::TxIn,
    prev_fk_hint: Option<rbitcoin_primitives::Fk>,
    txid_index: &TxidMap<usize>,
    spend_ti: usize,
    batch_parents: &rbitcoin_query::BatchParents,
    bip16: bool,
    witness: bool,
    need_script_buf: bool,
    wire: Option<&Arc<Block>>,
    acc: &mut AsmPrevoutAcc,
) -> Result<ResolvedPrevout, ConsensusError> {
    let prev_txid = op.txid.to_byte_array();

    if let Some(&pj) = txid_index.get(&prev_txid) {
        if pj < spend_ti {
            let tx = block.txdata.get(pj).ok_or(ConsensusError::MissingPrevout)?;
            let v = op.vout as usize;
            let o = tx.output.get(v).ok_or(ConsensusError::MissingPrevout)?;
            acc.in_n = acc.in_n.saturating_add(1);
            acc.same_n = acc.same_n.saturating_add(1);
            let shared = if need_script_buf {
                wire.map(|_| rbitcoin_query::SharedPrevoutScript::Wire {
                    tx_index: pj as u32,
                    vout: op.vout,
                })
            } else {
                None
            };
            return Ok(ResolvedPrevout {
                txout: if shared.is_some() || !need_script_buf {
                    TxOut {
                        value: o.value,
                        script_pubkey: ScriptBuf::new(),
                    }
                } else {
                    o.clone()
                },
                shared,
                input_sigops: prevout_spk_sigops(inp, o.script_pubkey.as_bytes(), bip16, witness),
                create_fk: rbitcoin_primitives::Fk::NULL,
            });
        }
    }

    // Batch pin first (no TxRecord clone — A3). Pin identity/vout misses are
    // hard invariants (load must fill schema-13 identity + denserels).
    if let Some(prev_fk) = prev_fk_hint {
        if let Some((pinned, parent_txid)) = batch_parents.share_parent_prevout(prev_fk, op.vout) {
            if parent_txid != prev_txid {
                acc.cold_txid_mismatch_n = acc.cold_txid_mismatch_n.saturating_add(1);
                #[cfg(test)]
                confirm_phase_stats::tl_note_cold_why_txid_mismatch();
                return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                    "invariant: pin parent create identity mismatch wire prev_txid",
                )));
            }
            let (value, input_sigops) = {
                let (value, script) = pinned.parts().ok_or(ConsensusError::Store(
                    rbitcoin_store::StoreError::Corrupt(
                        "invariant: pin incomplete outs for spent parent vout",
                    ),
                ))?;
                (value, prevout_spk_sigops(inp, script, bip16, witness))
            };
            acc.in_n = acc.in_n.saturating_add(1);
            acc.batch_n = acc.batch_n.saturating_add(1);
            #[cfg(test)]
            confirm_phase_stats::tl_note_batch_hit();
            return Ok(ResolvedPrevout {
                txout: TxOut {
                    value: Amount::from_sat(value as u64),
                    script_pubkey: ScriptBuf::new(),
                },
                shared: need_script_buf.then_some(pinned),
                input_sigops,
                create_fk: prev_fk,
            });
        } else if batch_parents.contains(prev_fk) {
            acc.cold_vout_miss_n = acc.cold_vout_miss_n.saturating_add(1);
            #[cfg(test)]
            confirm_phase_stats::tl_note_cold_why_vout_miss();
            return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                "invariant: pin incomplete outs for spent parent vout",
            )));
        }
    }

    Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
        "invariant: lookup stage miss (assemble parent create_fk)",
    )))
}

fn is_anyone_can_spend(script: &Script) -> bool {
    crate::script::is_anyone_can_spend(script)
}

pub use rbitcoin_query::TxPrecompute;

#[cfg(test)]
mod overlay_meta_skip_tests {
    use super::*;
    use rbitcoin_primitives::Fk;

    fn spends(rows: &[(u32, Fk, Fk, u32)]) -> Vec<([u8; 32], u32, Fk, Fk, u32)> {
        rows.iter()
            .map(|&(vout, sfk, cfk, vin)| ([0u8; 32], vout, sfk, cfk, vin))
            .collect()
    }

    #[test]
    fn overlay_meta_skip_omits_matching_abs() {
        let wave = ClassAWave::new(vec![Fk(10)]);
        let mut map = FkMap::default();
        map.insert(Fk(10), (5, false));
        let run = RunCreateHeight::Map(map);
        assert_eq!(run.create(Fk(10)), Some((5, false)));
        let spends = spends(&[(0, Fk(11), Fk(10), 0)]);
        let mut scratch = StructuralScratch::default();
        fill_overlay_skip(&spends, &wave, &mut scratch);
        assert!(overlay_meta_is_skip(10, 0, Fk(11), 0, &scratch.skip));
        assert!(!overlay_meta_is_skip(10, 0, Fk(11), 1, &scratch.skip));
        assert!(!overlay_meta_is_skip(10, 1, Fk(11), 0, &scratch.skip));
        assert!(!overlay_meta_is_skip(99, 0, Fk(11), 0, &scratch.skip));
    }

    #[test]
    fn overlay_meta_skip_keeps_conflicting_spender_on_disk_list() {
        let wave = ClassAWave::new(vec![Fk(10)]);
        let mut map = FkMap::default();
        map.insert(Fk(10), (5, false));
        let run = RunCreateHeight::Map(map);
        assert_eq!(run.create(Fk(10)), Some((5, false)));
        let spends = spends(&[(0, Fk(11), Fk(10), 0), (0, Fk(12), Fk(10), 0)]);
        let mut scratch = StructuralScratch::default();
        fill_overlay_skip(&spends, &wave, &mut scratch);
        assert!(!overlay_meta_is_skip(10, 0, Fk(11), 0, &scratch.skip));
        assert!(!overlay_meta_is_skip(10, 0, Fk(12), 0, &scratch.skip));
    }

    #[test]
    fn overlay_meta_skip_historical_create_stays_on_disk() {
        let wave = ClassAWave::default();
        let spends = spends(&[(0, Fk(11), Fk(10), 0)]);
        let mut scratch = StructuralScratch::default();
        fill_overlay_skip(&spends, &wave, &mut scratch);
        assert!(!overlay_meta_is_skip(10, 0, Fk(11), 0, &scratch.skip));
    }
}

#[cfg(test)]
mod run_create_height_tests {
    use super::RunCreateHeight;
    use rbitcoin_primitives::Fk;

    fn fk(id: u64) -> Fk {
        Fk(id)
    }

    #[test]
    fn run_create_height_span_misses_gaps() {
        let one = [fk(10), fk(11)];
        let idx = RunCreateHeight::from_blocks([(7u32, one.as_slice())]);
        assert!(matches!(idx, RunCreateHeight::Spans(_)));
        assert_eq!(idx.get(fk(10)), Some(7));
        assert_eq!(idx.get(fk(11)), Some(7));
        assert_eq!(idx.get(fk(9)), None);
        assert_eq!(idx.get(fk(12)), None);

        let low = [fk(10), fk(11)];
        let high = [fk(20), fk(21)];
        let idx = RunCreateHeight::from_blocks([(1u32, low.as_slice()), (2, high.as_slice())]);
        assert_eq!(idx.get(fk(15)), None);
        assert_eq!(idx.get(fk(10)), Some(1));
        assert_eq!(idx.get(fk(21)), Some(2));

        let gapped = [fk(1), fk(2), fk(4)];
        let idx = RunCreateHeight::from_blocks([(3u32, gapped.as_slice())]);
        assert!(matches!(idx, RunCreateHeight::Map(_)));
        assert_eq!(idx.get(fk(3)), None);
        assert_eq!(idx.get(fk(1)), Some(3));
        assert_eq!(idx.get(fk(2)), Some(3));
        assert_eq!(idx.get(fk(4)), Some(3));
    }

    #[test]
    fn run_create_height_marks_each_block_first_fk_coinbase() {
        let low = [fk(10), fk(11)];
        let high = [fk(12), fk(13)];
        let idx = RunCreateHeight::from_blocks([(1u32, low.as_slice()), (2, high.as_slice())]);
        assert!(matches!(idx, RunCreateHeight::Spans(_)));
        assert_eq!(idx.create(fk(10)), Some((1, true)));
        assert_eq!(idx.create(fk(11)), Some((1, false)));
        assert_eq!(idx.create(fk(12)), Some((2, true)));
        assert_eq!(idx.create(fk(13)), Some((2, false)));

        let gapped = [fk(20), fk(22)];
        let idx = RunCreateHeight::from_blocks([(1u32, low.as_slice()), (2, gapped.as_slice())]);
        assert!(matches!(idx, RunCreateHeight::Map(_)));
        assert_eq!(idx.create(fk(10)), Some((1, true)));
        assert_eq!(idx.create(fk(11)), Some((1, false)));
        assert_eq!(idx.create(fk(20)), Some((2, true)));
        assert_eq!(idx.create(fk(22)), Some((2, false)));
        assert_eq!(idx.create(fk(21)), None);
    }
}

#[cfg(test)]
mod bip34_tests;
#[cfg(test)]
mod block_866342;
#[cfg(test)]
mod finality_tests;
#[cfg(test)]
mod sigop_cost_tests;
#[cfg(test)]
mod structure_rule_tests;
#[cfg(test)]
mod taproot_batch_bench_tests;
