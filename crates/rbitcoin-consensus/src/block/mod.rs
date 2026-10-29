use crate::error::ConsensusError;
use crate::milestone::Milestone;
use crate::params::ChainParams;
use crate::TxidHasher;
use bitcoin::block::Block;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::script::{Script, ScriptBuf};
use bitcoin::{Amount, Transaction, TxOut, Witness};
use rbitcoin_primitives::Height;
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

pub const MAX_BLOCK_STRIPPED_SIZE: usize = 1_000_000;
/// Consensus block weight limit. Compact-block tx count is this divided by
/// [`MIN_TX_WEIGHT`].
pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
/// Minimum serializable transaction weight (10 bytes × witness scale 4).
pub const MIN_TX_WEIGHT: u64 = 10 * 4;
/// Most transactions a valid block can contain.
pub const MAX_BLOCK_TX_COUNT: usize = (MAX_BLOCK_WEIGHT / MIN_TX_WEIGHT) as usize;

pub fn check_tx_local(tx: &Transaction, base_size: usize) -> Result<(), ConsensusError> {
    if tx.input.is_empty() {
        return Err(ConsensusError::BadTx("no inputs"));
    }
    if tx.output.is_empty() {
        return Err(ConsensusError::BadTx("no outputs"));
    }
    if base_size > MAX_BLOCK_STRIPPED_SIZE {
        return Err(ConsensusError::BadTx("bad-txns-oversize"));
    }
    if tx.is_coinbase() {
        return Ok(());
    }
    for inp in &tx.input {
        if inp.previous_output.is_null() {
            return Err(ConsensusError::BadTx("bad-txns-prevout-null"));
        }
    }
    Ok(())
}

fn reject_duplicate_outpoints(
    tx: &Transaction,
    seen: &mut crate::OutPointSet,
) -> Result<(), ConsensusError> {
    seen.clear();
    seen.reserve(tx.input.len());
    for inp in &tx.input {
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
pub fn validate_block_structure_precomputed(
    block: &Block,
    ctx: &ValidationContext<'_>,
) -> Result<Vec<TxPrecompute>, ConsensusError> {
    Ok(validate_block_structure_with_pres(block, ctx, None, None)?.to_vec())
}

#[doc(hidden)]
pub fn reject_bad_block_tx_layout(
    block: &Block,
    pres: &[TxPrecompute],
) -> Result<(), ConsensusError> {
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
    mut note: Option<&mut dyn FnMut(u64, u64, u64)>,
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
    let (merkle, mutated) = rbitcoin_primitives::merkle_root_mutated(&txids);
    if merkle != block.header.merkle_root.to_byte_array() {
        // Duplicate txids under a root the header does not commit to stay a
        // merkle miss. That body is not this block.
        return Err(ConsensusError::BadBlock("merkle root mismatch"));
    } else if mutated {
        return Err(ConsensusError::BadBlock("bad-txns-duplicate"));
    }
    // One set for the block. A one-input tx cannot repeat an outpoint, so it
    // does not allocate. Runs before the coinbase layout check: two null
    // coinbase inputs are `bad-txns-inputs-duplicate`, not "first tx not coinbase".
    let mut block_outs: Option<crate::OutPointSet> = None;
    for tx in &block.txdata {
        if tx.input.len() < 2 {
            continue;
        }
        let seen = block_outs.get_or_insert_with(|| {
            crate::OutPointSet::with_capacity_and_hasher(tx.input.len(), Default::default())
        });
        reject_duplicate_outpoints(tx, seen)?;
    }
    reject_bad_block_tx_layout(block, &pres)?;

    // Core CheckTransaction: after the root matches, so a swapped scriptSig is
    // a merkle mismatch, and before ContextualCheckBlock's BIP34 height.
    let cb_ss = block.txdata[0].input[0].script_sig.len();
    if !(2..=100).contains(&cb_ss) {
        return Err(ConsensusError::BadBlock("bad-cb-length"));
    }

    let mut seen: crate::TxidSet = crate::TxidSet::with_capacity_and_hasher(n, Default::default());
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
        let mut cost = 0u64;
        for p in pres.iter() {
            cost = cost.saturating_add(p.sigops.saturating_mul(WITNESS_SCALE));
        }
        if cost > MAX_BLOCK_SIGOPS_COST {
            crate::trust::soften(ConsensusError::BadBlock("bad-blk-sigops"))?;
        }
    }
    let walk_ns = t_walk.elapsed().as_nanos() as u64;

    if let Some(note) = note.as_mut() {
        note(txid_ns, 0, walk_ns);
    }

    // BIP325 signet solution is not checked here — tip confirm only.

    Ok(pres)
}

/// Witness commitment before weight. Padding is not the block hash's fault.
#[doc(hidden)]
pub fn reject_witness_malleation(
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

#[doc(hidden)]
pub fn coinbase_has_witness_commitment(block: &Block) -> bool {
    block
        .txdata
        .first()
        .and_then(witness_commitment_vout_index)
        .is_some()
}

/// BIP141 witness-commitment script prefix (`OP_RETURN` `6a24aa21a9ed`).
const WITNESS_COMMITMENT_MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// Last BIP141 `OP_RETURN` witness commitment (exact 38-byte `6a24aa21a9ed` prefix).
pub fn witness_commitment_vout_index(coinbase: &Transaction) -> Option<usize> {
    coinbase
        .output
        .iter()
        .enumerate()
        .rev()
        .find_map(|(i, out)| {
            let b = out.script_pubkey.as_bytes();
            (b.len() >= 38 && b[..6] == WITNESS_COMMITMENT_MAGIC).then_some(i)
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

/// Same as [`block_has_witness`] from each row's `has_witness` flag (no second walk).
#[inline]
pub fn block_has_witness_from_pres(pres: &[TxPrecompute]) -> bool {
    pres.iter().any(|p| p.has_witness)
}

/// Coinbase wtxid is 32 zero bytes, then the non-coinbase wtxids. Commitment is
/// `sha256d(witness_merkle_root || reserved)`.
fn witness_commitment_digest(
    non_cb_wtxids: impl IntoIterator<Item = [u8; 32]>,
    reserved: &[u8; 32],
) -> [u8; 32] {
    let mut leaves = vec![[0u8; 32]];
    leaves.extend(non_cb_wtxids);
    let witness_root = merkle_root_bytes(&leaves);
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&witness_root);
    buf[32..].copy_from_slice(reserved);
    sha256d::Hash::hash(&buf).to_byte_array()
}

/// BIP141 coinbase `OP_RETURN` script for GBT `default_witness_commitment`.
pub fn witness_commitment_script(
    non_cb_wtxids: impl IntoIterator<Item = [u8; 32]>,
    reserved: &[u8; 32],
) -> Vec<u8> {
    let mut spk = Vec::with_capacity(38);
    spk.extend_from_slice(&WITNESS_COMMITMENT_MAGIC);
    spk.extend_from_slice(&witness_commitment_digest(non_cb_wtxids, reserved));
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

pub use rbitcoin_primitives::script_sigop_count;

/// Last push in a script for P2SH/BIP141 sigops.
///
/// Opcode `> OP_16` or a truncated push → no redeem (0 sigops). OP_N / OP_1NEGATE
/// count as an empty push.
pub fn last_script_push(script: &[u8]) -> Option<&[u8]> {
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

/// BIP16 P2SH sigops from redeem scripts (accurate CHECKMULTISIG count).
#[doc(hidden)]
pub fn p2sh_sigops_one(inp: &bitcoin::TxIn, spk: &[u8]) -> u64 {
    if !Script::from_bytes(spk).is_p2sh() {
        return 0;
    }
    last_script_push(inp.script_sig.as_bytes())
        .map(|redeem| script_sigop_count(redeem, true))
        .unwrap_or(0)
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn p2sh_sigop_count(tx: &Transaction, prev_spks: &[&[u8]]) -> u64 {
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
#[doc(hidden)]
pub fn witness_sigops_one(inp: &bitcoin::TxIn, spk: &[u8]) -> u64 {
    let mut program = spk;
    if Script::from_bytes(program).is_p2sh() {
        if let Some(redeem) = last_script_push(inp.script_sig.as_bytes()) {
            program = redeem;
        } else {
            return 0;
        }
    }
    let program = Script::from_bytes(program);
    if program.is_p2wpkh() {
        1
    } else if program.is_p2wsh() {
        inp.witness
            .last()
            .map(|ws| script_sigop_count(ws, true))
            .unwrap_or(0)
    } else {
        0
    }
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn witness_sigop_count(tx: &Transaction, prev_spks: &[&[u8]]) -> u64 {
    let mut n = 0u64;
    for (i, inp) in tx.input.iter().enumerate() {
        let Some(spk) = prev_spks.get(i) else {
            continue;
        };
        n = n.saturating_add(witness_sigops_one(inp, spk));
    }
    n
}

pub fn prevout_spk_sigops(inp: &bitcoin::TxIn, spk: &[u8], bip16: bool, witness: bool) -> u64 {
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
#[doc(hidden)]
pub fn check_witness_commitment_with_wtxids(
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
    let mut reserved_arr = [0u8; 32];
    reserved_arr.copy_from_slice(reserved);
    let hash = witness_commitment_digest(precomputed_non_cb.iter().copied(), &reserved_arr);
    if hash != committed {
        return Err(ConsensusError::BadBlock("witness commitment mismatch"));
    }
    Ok(())
}

/// Merkle root over 32-byte leaves (txid or wtxid tree). Public for tests.
pub fn merkle_root_bytes(leaves: &[[u8; 32]]) -> [u8; 32] {
    rbitcoin_primitives::merkle_root_from_txids(leaves)
}

/// BIP34: coinbase scriptSig must start with the block height as a script integer
/// push: 0 → `OP_0`; 1..=16 → `OP_1`..=`OP_16`; else minimal sign-aware little-endian.
pub fn check_bip34_coinbase(coinbase: &Transaction, height: u32) -> Result<(), ConsensusError> {
    let script = &coinbase.input[0].script_sig;
    let bytes = script.as_bytes();
    if bytes.is_empty() {
        return crate::trust::soften(ConsensusError::BadBlock("bip34 coinbase script empty"));
    }
    let expected = bip34_height_script(height);
    if bytes.len() < expected.len() || &bytes[..expected.len()] != expected.as_slice() {
        return crate::trust::soften(ConsensusError::BadBlock("bip34 height encoding"));
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
    let num = rbitcoin_primitives::scriptnum_encode(i64::from(height));
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
#[doc(hidden)]
pub const BIP16_EXCEPTION_TESTNET3: [u8; 32] = [
    // little-endian display hash 00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105
    0x05, 0xb1, 0x32, 0xa4, 0xf7, 0x4a, 0x87, 0x99, 0xa5, 0x7a, 0x42, 0x02, 0xd0, 0xee, 0xb0, 0x96,
    0x12, 0xcc, 0x08, 0xd2, 0x95, 0x40, 0x1f, 0x00, 0x7c, 0x45, 0x30, 0xdd, 0x00, 0x00, 0x00, 0x00,
];

/// BIP16 P2SH from **precomputed** prev MTP + block hash (no header re-walk, no rehash).
///
/// Callers must pass the same prev-block MTP used for BIP113 / header MTP checks
/// and the once-computed block hash (plan `meta.hash` / structure).
pub fn bip16_active_from_prev_mtp(
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
pub struct JobTx {
    pub inner: JobTxInner,
}

#[derive(Clone)]
#[doc(hidden)]
pub enum JobTxInner {
    Owned(Transaction),
    Shared { block: Arc<Block>, index: usize },
}

impl JobTx {
    #[inline]
    pub fn owned(tx: Transaction) -> Self {
        Self {
            inner: JobTxInner::Owned(tx),
        }
    }

    #[inline]
    pub fn shared(block: Arc<Block>, index: usize) -> Self {
        debug_assert!(index < block.txdata.len());
        Self {
            inner: JobTxInner::Shared { block, index },
        }
    }

    #[doc(hidden)]
    pub fn output_at(&self, tx_index: u32, vout: u32) -> Option<&TxOut> {
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
/// use an explicit struct literal.
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

/// Bytes of one pinned prevout. The `Arc` is the pin allocation; `parts`
/// borrows the script inside it (no second copy).
pub trait PinParts: Send + Sync {
    fn parts(&self, vout: u32) -> Option<(u64, &[u8])>;
}

/// Prevout a confirm job reads without copying script bytes.
///
/// `Wire` is `(tx_index, vout)` in the job's wire block. `Pinned` is one vout
/// of the pin outs `Arc`.
#[derive(Clone)]
pub enum SharedPrevout {
    Wire { tx_index: u32, vout: u32 },
    Pinned { outs: Arc<dyn PinParts>, vout: u32 },
}

/// Prevout scripts for one script job.
///
/// Owned jobs (tests, non-wire connect) store [`TxOut`]. Confirm jobs store
/// [`SharedPrevout`]: same-block bytes stay in the wire block, historical
/// bytes stay in the pin outs `Arc`.
#[derive(Clone)]
pub enum JobPrevouts {
    Owned(Vec<TxOut>),
    Shared(Vec<SharedPrevout>),
}

impl JobPrevouts {
    pub fn owned(v: Vec<TxOut>) -> Self {
        Self::Owned(v)
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Owned(v) => v.len(),
            Self::Shared(v) => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Input index yielded by [`ScriptCheckJob::inputs`].
///
/// Only a job builds this. A bare `usize` cannot name an input the transaction
/// does not have.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InputIndex(u32);

impl InputIndex {
    #[inline]
    pub fn get(self) -> usize {
        self.0 as usize
    }

    /// Index `i` of `tx`. Out of range is a caller bug, not a script result.
    #[inline]
    pub(crate) fn in_tx(tx: &Transaction, i: usize) -> Result<Self, ConsensusError> {
        if i >= tx.input.len() {
            return Err(ConsensusError::Script("input index".into()));
        }
        Ok(Self(i as u32))
    }

    /// Position in a prevout list the caller already matched to `vin`.
    #[inline]
    pub(crate) fn at(i: usize) -> Self {
        Self(i as u32)
    }
}

/// Script-verify job for one non-coinbase create.
///
/// Confirm assemble attaches the wire [`Arc<Block>`] (no tx deep-clone). `txid`
/// is the structure/plan hash so scripts can probe mempool preverified without
/// re-hashing. Prevouts and inputs have the same length; build with
/// [`ScriptCheckJob::try_new`] or [`ScriptCheckJob::try_from_parts`].
#[non_exhaustive]
pub struct ScriptCheckJob {
    /// Wire txid (assemble / [`Self::new`]); used for mempool preverified skip.
    pub txid: [u8; 32],
    pub prevouts: JobPrevouts,
    /// Owned (tests) or shared wire block + index (confirm path).
    pub tx: JobTx,
    pub flags: ScriptVerifyFlags,
    /// Lookup/structure `TxPrecompute`. Set on the confirm path; tests lazy-`from_tx`.
    pub pre: std::sync::OnceLock<JobPre>,
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
pub enum JobPre {
    Owned(std::sync::Arc<crate::TxPrecompute>),
    Slice {
        slice: std::sync::Arc<[crate::TxPrecompute]>,
        idx: usize,
    },
}

impl ScriptCheckJob {
    /// One index per input. Empty when `vin` is empty.
    #[inline]
    pub fn inputs(&self) -> impl Iterator<Item = InputIndex> {
        let n = self.tx.input.len() as u32;
        (0..n).map(InputIndex)
    }

    /// Build a job hashing `tx` once for [`Self::txid`] (tests / detached verify).
    ///
    /// Panics when `prevouts.len() != tx.input.len()`. Callers that must surface
    /// that as [`ConsensusError::Script`] use [`Self::try_new`].
    #[inline]
    pub fn new(prevouts: Vec<TxOut>, tx: Transaction, flags: ScriptVerifyFlags) -> Self {
        Self::try_new(prevouts, tx, flags).expect("prevout count")
    }

    /// Owned-tx path (tests / benches / unit connect): reuse precomputed txid.
    ///
    /// Panics when `prevouts.len() != tx.input.len()`.
    #[inline]
    pub fn with_txid(
        txid: [u8; 32],
        prevouts: Vec<TxOut>,
        tx: Transaction,
        flags: ScriptVerifyFlags,
    ) -> Self {
        Self::try_with_txid(txid, prevouts, tx, flags).expect("prevout count")
    }

    /// Build a job hashing `tx` once for [`Self::txid`] (tests / detached verify).
    #[inline]
    pub fn try_new(
        prevouts: Vec<TxOut>,
        tx: Transaction,
        flags: ScriptVerifyFlags,
    ) -> Result<Self, ConsensusError> {
        use bitcoin::hashes::Hash;
        let txid = tx.compute_txid().to_byte_array();
        Self::try_with_txid(txid, prevouts, tx, flags)
    }

    /// Owned-tx path (tests / benches / unit connect): reuse precomputed txid.
    #[inline]
    pub fn try_with_txid(
        txid: [u8; 32],
        prevouts: Vec<TxOut>,
        tx: Transaction,
        flags: ScriptVerifyFlags,
    ) -> Result<Self, ConsensusError> {
        Self::try_from_parts(txid, JobPrevouts::owned(prevouts), JobTx::owned(tx), flags)
    }

    /// Rejects a prevout list whose length is not `vin`.
    #[inline]
    pub fn try_from_parts(
        txid: [u8; 32],
        prevouts: JobPrevouts,
        tx: JobTx,
        flags: ScriptVerifyFlags,
    ) -> Result<Self, ConsensusError> {
        if prevouts.len() != tx.input.len() {
            return Err(ConsensusError::Script("prevout count".into()));
        }
        if let JobPrevouts::Shared(slots) = &prevouts {
            for slot in slots {
                if let SharedPrevout::Wire { tx_index, vout } = slot {
                    if tx.output_at(*tx_index, *vout).is_none() {
                        return Err(ConsensusError::MissingPrevout);
                    }
                }
            }
        }
        Ok(Self::from_parts(txid, prevouts, tx, flags))
    }

    #[inline]
    fn from_parts(
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
    ///
    /// A connect-only row has no sighash midstates. Assemble rejects it here
    /// so script verify does not discover that on the worker.
    #[inline]
    pub fn with_pre_slice(
        self,
        slice: std::sync::Arc<[crate::TxPrecompute]>,
        idx: usize,
    ) -> Result<Self, ConsensusError> {
        let Some(row) = slice.get(idx) else {
            return Err(ConsensusError::Internal("invariant: precompute index"));
        };
        if row.as_script().is_none() {
            return Err(ConsensusError::Internal(
                "invariant: sighash midstate missing",
            ));
        }
        let _ = self.pre.set(JobPre::Slice { slice, idx });
        Ok(self)
    }

    #[doc(hidden)]
    pub fn job_pre(&self) -> &JobPre {
        self.pre.get_or_init(|| {
            JobPre::Owned(std::sync::Arc::new(crate::TxPrecompute::from_tx(&self.tx)))
        })
    }

    /// Amount and script bytes for input `i`.
    ///
    /// Shared wire prevouts read the job's block. A wire slot past `n_out` is
    /// [`ConsensusError::MissingPrevout`] from [`Self::try_from_parts`]. Pinned
    /// prevouts read the outs `Arc`.
    pub fn prevout_parts(&self, i: InputIndex) -> Result<(u64, &[u8]), ConsensusError> {
        let i = i.get();
        match &self.prevouts {
            JobPrevouts::Owned(v) => {
                let o = &v[i];
                Ok((o.value.to_sat(), o.script_pubkey.as_bytes()))
            }
            JobPrevouts::Shared(v) => {
                let slot = &v[i];
                match slot {
                    SharedPrevout::Wire { tx_index, vout } => {
                        let o = self
                            .tx
                            .output_at(*tx_index, *vout)
                            .expect("wire prevout resolved when the job was built");
                        Ok((o.value.to_sat(), o.script_pubkey.as_bytes()))
                    }
                    SharedPrevout::Pinned { outs, vout } => outs
                        .parts(*vout)
                        .ok_or(ConsensusError::Internal("invariant: pinned prevout vout")),
                }
            }
        }
    }

    #[inline]
    pub fn prevout_script(&self, i: InputIndex) -> Result<&[u8], ConsensusError> {
        self.prevout_parts(i).map(|(_, script)| script)
    }

    #[inline]
    pub fn prevout_amount(&self, i: InputIndex) -> Result<Amount, ConsensusError> {
        self.prevout_parts(i)
            .map(|(value, _)| Amount::from_sat(value))
    }

    #[inline]
    pub fn pre(&self) -> Result<&crate::TxScriptPrecompute, ConsensusError> {
        let row = match self.job_pre() {
            JobPre::Owned(a) => a.as_ref(),
            JobPre::Slice { slice, idx } => slice
                .get(*idx)
                .ok_or(ConsensusError::Internal("invariant: precompute index"))?,
        };
        row.as_script().ok_or(ConsensusError::Internal(
            "invariant: sighash midstate missing",
        ))
    }
}

/// Identity-hashed `txid → V` (assemble index / pack creates).
pub type TxidMap<V> = std::collections::HashMap<[u8; 32], V, BuildHasherDefault<TxidHasher>>;

/// Pack-local create fk by parent txid (not per-vout — fk is per tx).
pub type PendingCreates = TxidMap<rbitcoin_primitives::Fk>;

/// `MAX_BLOCK_SIGOPS_COST` (20_000 legacy sigops × witness scale 4).
#[inline]
pub fn exceeds_sigops_limit(cost: u64) -> bool {
    cost > MAX_BLOCK_SIGOPS_COST
}

/// Attach the precompute slice only when `ti` is inside it.
#[inline]
pub fn should_use_pres(ti: usize, len: usize) -> bool {
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
pub fn exceeds_max_money(sats: u64) -> bool {
    sats > Amount::MAX_MONEY.to_sat()
}

/// Signed satoshis for an `out_sum` that already passed [`exceeds_max_money`].
#[inline]
pub fn money_range_out_sum(out_sum: u64) -> i64 {
    debug_assert!(
        !exceeds_max_money(out_sum),
        "out_sum above MAX_MONEY must be rejected in validate_block_structure_with_pres"
    );
    out_sum as i64
}

pub fn assemble_tx_value_out(
    tx: &Transaction,
    ti: usize,
    pres: Option<&Arc<[crate::TxPrecompute]>>,
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

pub fn check_coinbase_subsidy(
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
        return crate::trust::soften(ConsensusError::BadBlock("coinbase excess value"));
    }
    Ok(())
}

/// BIP30: an earlier connected instance with an unspent spendable output may
/// not be overwritten. The same height is this block.
pub fn reject_bip30_unspent_prior(
    spend_height: u32,
    prior_height: u32,
    unspent_spendable: bool,
) -> Result<(), ConsensusError> {
    if prior_height != spend_height && unspent_spendable {
        return crate::trust::soften(ConsensusError::BadTx("bad-txns-BIP30"));
    }
    Ok(())
}

/// Create-height facts for one spent output. `None` is not a coin. A later
/// height in this batch is not yet a coin. A coinbase inside maturity is not
/// spendable.
pub fn reject_one_create(
    spend_height: u32,
    maturity: u32,
    create_height: Option<u32>,
    is_coinbase: bool,
) -> Result<(), ConsensusError> {
    let Some(create_height) = create_height else {
        return Err(ConsensusError::BadTx("bad-txns-inputs-missingorspent"));
    };
    if create_height > spend_height {
        return Err(ConsensusError::MissingPrevout);
    }
    if is_coinbase && spend_height < create_height.saturating_add(maturity) {
        return crate::trust::soften(ConsensusError::BadTx("coinbase immature"));
    }
    Ok(())
}

/// Whether this job can skip `verify_job_all_inputs`.
///
/// OP_TRUE scriptPubKey alone is **not** sufficient: scriptSig still runs
/// (CLTV/CSV may live there). Only skip when every input is a pure ACS spend
/// (empty scriptSig + empty witness + OP_TRUE spk).
#[doc(hidden)]
pub fn job_needs_script_check(job: &ScriptCheckJob) -> bool {
    let tx: &bitcoin::Transaction = &job.tx;
    for i in job.inputs() {
        let Ok(spk) = job.prevout_script(i) else {
            return true;
        };
        if !is_anyone_can_spend(Script::from_bytes(spk)) {
            return true;
        }
        let vin = &tx.input[i.get()];
        if !vin.script_sig.is_empty() || !vin.witness.is_empty() {
            return true;
        }
    }
    false
}

#[inline]
pub fn verify_one_script_job(job: &ScriptCheckJob) -> Result<(), ConsensusError> {
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

/// BIP65/113 nLockTime threshold: values below are block heights, above are unix times.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// BIP141 witness scale factor. Legacy sigops are multiplied by this.
pub const WITNESS_SCALE: u64 = 4;

/// BIP141 block sigop-cost limit (`20_000` legacy sigops × [`WITNESS_SCALE`]).
pub const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;

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

#[doc(hidden)]
pub fn is_anyone_can_spend(script: &Script) -> bool {
    crate::script::is_anyone_can_spend(script)
}

#[doc(hidden)]
pub mod facts;
pub use facts::{
    add_fee, add_sigops, add_value_in, fee_from_values, fee_sat, fee_with_waived_coinbase,
    header_gap_on_chain, median_or_bad_header, reject_assemble_block_shape, reject_batch_starts_at,
    reject_bits, reject_carried_header_hash, reject_confirm_batch, reject_csv_create_height,
    reject_duplicate_input, reject_empty_confirm_batch, reject_genesis_coinbase_spend,
    reject_non_final, reject_prev_link, reject_prevout_spent, reject_same_block_create,
    reject_sequence_locks, reject_spend_cursor, reject_tx_without_inputs,
    reject_tx_without_outputs, reject_txid_count, reject_unresolved_spend,
    reject_unspendable_prevout, reject_vout_past_n_out, reject_witness_before_segwit,
    require_linked_parent, require_next_work, require_retarget_first, require_same_block_output,
    unresolved_parent_create, waived_output_residue,
};

pub use crate::TxPrecompute;
