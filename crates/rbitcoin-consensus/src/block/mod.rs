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
use std::sync::atomic::Ordering;
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
    /// enforced at **confirm** with the true height. Merkle / weight / witness
    /// **commitment** still run here either way.
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
    for (i, inp) in tx.input.iter().enumerate() {
        if !tx.is_coinbase() && inp.previous_output.is_null() {
            return Err(ConsensusError::BadTx("bad-txns-prevout-null"));
        }
        for prev in &tx.input[..i] {
            if prev.previous_output == inp.previous_output {
                return Err(ConsensusError::BadTx("bad-txns-inputs-duplicate"));
            }
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
    Ok(validate_block_structure_with_pres(block, ctx, None)?.to_vec())
}

/// Like [`validate_block_structure_precomputed`], reusing lookup-stashed pres
/// when `pres` is `Some` (no second `from_tx`). Length must match `txdata`.
/// Caller Arc is returned as-is (refcount only).
pub fn validate_block_structure_with_pres(
    block: &Block,
    ctx: &ValidationContext<'_>,
    pres: Option<Arc<[TxPrecompute]>>,
) -> Result<Arc<[TxPrecompute]>, ConsensusError> {
    if block.txdata.is_empty() {
        return Err(ConsensusError::BadBlock("no transactions"));
    }
    if !block.txdata[0].is_coinbase() {
        return Err(ConsensusError::BadBlock("first tx not coinbase"));
    }
    for tx in block.txdata.iter().skip(1) {
        if tx.is_coinbase() {
            return Err(ConsensusError::BadBlock("coinbase not first"));
        }
    }

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
    let mut seen = std::collections::HashSet::with_capacity(n);
    for p in pres.iter() {
        if !seen.insert(p.txid) {
            return Err(ConsensusError::BadBlock("duplicate txid"));
        }
    }

    let t_walk = Instant::now();
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
    if weight_wu > 4_000_000 {
        return Err(ConsensusError::BadBlock("block weight too large"));
    }

    let txids: Vec<[u8; 32]> = pres.iter().map(|p| p.txid).collect();
    let merkle = merkle_root_bytes(&txids);
    if merkle != block.header.merkle_root.to_byte_array() {
        return Err(ConsensusError::BadBlock("merkle root mismatch"));
    }

    // BIP34 only after the network's buried height (mainnet 227931). From
    // height 1 this rejects mainnet block 1.
    if ctx.enforce_height_gates && ctx.params.bip34_active_at(ctx.height.0) {
        check_bip34_coinbase(&block.txdata[0], ctx.height.0)?;
    }

    {
        let cb_ss = block.txdata[0].input[0].script_sig.as_bytes().len();
        if cb_ss < 2 || cb_ss > 100 {
            return Err(ConsensusError::BadBlock("bad-cb-length"));
        }
    }

    const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
    for (tx, p) in block.txdata.iter().zip(pres.iter()) {
        check_tx_local(tx, p.base_size)?;
        for o in &tx.output {
            if o.value.to_sat() > MAX_MONEY {
                return Err(ConsensusError::BadBlock("bad-txns-vout-toolarge"));
            }
        }
        if p.out_sum > MAX_MONEY {
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

    let has_witness_data = block_has_witness(block);
    let has_commitment = coinbase_has_witness_commitment(block);
    if has_witness_data && ctx.enforce_height_gates && !ctx.params.segwit_active_at(ctx.height.0) {
        return Err(ConsensusError::BadBlock("unexpected witness before segwit"));
    }
    // Core: BIP141 nonce only after SegWit. Pre-segwit aa21a9ed OP_RETURN is data.
    // Archive has no reliable height — still check.
    if (has_witness_data || has_commitment)
        && (ctx.params.segwit_active_at(ctx.height.0) || !ctx.enforce_height_gates)
    {
        let non_cb: Vec<[u8; 32]> = pres.iter().skip(1).map(|p| p.wtxid).collect();
        check_witness_commitment_with_wtxids(block, &non_cb)?;
    }

    crate::plan_stamp_sub_stats::note_struct_parts(txid_ns, 0, walk_ns);

    // BIP325 signet solution is not checked here — tip confirm only.

    Ok(pres)
}

fn coinbase_has_witness_commitment(block: &Block) -> bool {
    block
        .txdata
        .first()
        .and_then(witness_commitment_vout_index)
        .is_some()
}

/// Last BIP141 `OP_RETURN` witness commitment (exact 38-byte `6a24aa21a9ed` prefix).
pub(crate) fn witness_commitment_vout_index(coinbase: &Transaction) -> Option<usize> {
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

/// Last push in a script for P2SH/BIP141 sigops (Core `CScript::GetSigOpCount(scriptSig)`).
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

fn prevout_spk_sigops(inp: &bitcoin::TxIn, spk: &[u8], bip16: bool, segwit: bool) -> u64 {
    const WITNESS_SCALE: u64 = 4;
    let mut n = 0u64;
    if bip16 {
        n = n.saturating_add(p2sh_sigops_one(inp, spk).saturating_mul(WITNESS_SCALE));
    }
    if segwit {
        n = n.saturating_add(witness_sigops_one(inp, spk));
    }
    n
}

/// GBT `sigops`: Core `GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR`.
///
/// Full `GetTransactionSigOpCost` also adds P2SH/witness when prevouts are
/// known; template rows use this scaled legacy count (P2PK output = 4).
pub fn tx_gbt_sigops(tx: &Transaction) -> u64 {
    legacy_sigop_count(tx).saturating_mul(4)
}

/// Full Core-style sigop cost for one tx given prevout scripts (BIP16 + BIP141).
#[cfg(test)]
fn tx_sigop_cost(tx: &Transaction, prev_spks: &[&[u8]], bip16: bool, segwit: bool) -> u64 {
    const WITNESS_SCALE: u64 = 4;
    let mut cost = legacy_sigop_count(tx).saturating_mul(WITNESS_SCALE);
    if bip16 {
        cost = cost.saturating_add(p2sh_sigop_count(tx, prev_spks).saturating_mul(WITNESS_SCALE));
    }
    if segwit {
        cost = cost.saturating_add(witness_sigop_count(tx, prev_spks));
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

/// BIP34: coinbase scriptSig must start with the block height, encoded as Bitcoin
/// Core's `CScript << int64` push (not raw CScriptNum for small values).
///
/// Core `CScript::push_int64`:
/// - 0 → `OP_0` (0x00)
/// - 1..=16 → `OP_1`..=`OP_16` (0x51..=0x60)
/// - else → minimal CScriptNum (`len || little-endian bytes`, sign-aware)
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
    let n = height as i64;
    if n == 0 {
        return vec![0x00];
    }
    if (1..=16).contains(&n) {
        return vec![0x50 + n as u8];
    }
    let mut num = Vec::new();
    let mut abs = n;
    let neg = abs < 0;
    if neg {
        abs = -abs;
    }
    while abs > 0 {
        num.push((abs & 0xff) as u8);
        abs >>= 8;
    }
    if let Some(last) = num.last() {
        if last & 0x80 != 0 {
            num.push(if neg { 0x80 } else { 0x00 });
        } else if neg {
            let i = num.len() - 1;
            num[i] |= 0x80;
        }
    } else {
        num.push(0);
    }
    let mut out = Vec::with_capacity(1 + num.len());
    out.push(num.len() as u8);
    out.extend_from_slice(&num);
    out
}

/// Connect checks on contiguous tip confirm.
///
/// Pipeline (optimistic scripts, assumevalid-shaped):
/// 1. **Assemble** — resolve prevout *content*, intra-block doubles, fees; build jobs
///    (no durable spentness / maturity).
/// 2. **Scripts** — above milestone, script_pool (CPU; needs prevout values only).
/// 3. **Structural** — durable spentness, maturity, coinbase subsidy (order-sensitive).
///
/// Class C tip updates (`confirm_block`) stay outside this function.
///
/// `archived_tx_fks`: Class A fks for `block.txdata` (same order) when confirming
/// archived bodies (thin create_fk / Class A rows in parent cache).
///
/// **Production tip / IBD:** use [`crate::accept_and_connect_block`] or
/// [`crate::confirm_wire_run`] (lookup → load pin denserels → scripts → write). This
/// helper is a **no-write** unit-test surface (empty pin → store cold spentness).
/// It does not populate denserels and must not be the tip hot path.
pub fn validate_block_connect(
    query: &Query,
    block: &Block,
    ctx: &ValidationContext<'_>,
    archived_tx_fks: Option<&[rbitcoin_primitives::Fk]>,
) -> Result<(), ConsensusError> {
    if ctx.height.0 > 0 {
        if let Some(challenge) = ctx.params.signet_challenge.as_ref() {
            crate::signet::validate_signet_block_solution(block, challenge.as_script())?;
        }
    }

    let check_scripts = !ctx.milestone.skips_scripts_at(ctx.height.0);
    let mut pending = rbitcoin_query::OutPointSet::default();
    let mut pending_creates = PendingCreates::default();
    let batch_parents = rbitcoin_query::BatchParents::new();
    let spend_edges = rbitcoin_query::SpendEdges::default();
    let create_txids: Vec<[u8; 32]> = block
        .txdata
        .iter()
        .map(|t| t.compute_txid().to_byte_array())
        .collect();
    let block_hash = block.header.block_hash().to_byte_array();
    let prev_mtp = if ctx.height.0 == 0 {
        0
    } else {
        crate::header::median_time_past(query, Height(ctx.height.0 - 1)).unwrap_or(0)
    };
    let bip16_active = bip16_active_from_prev_mtp(ctx.params, ctx.height.0, &block_hash, prev_mtp);
    let (script_jobs, spends, fees) = assemble_block_prevouts(
        query,
        block,
        ctx,
        archived_tx_fks,
        &mut pending,
        &mut pending_creates,
        &batch_parents,
        &spend_edges,
        &create_txids,
        prev_mtp,
        &block_hash,
        bip16_active,
        None,
        None,
    )?;
    if check_scripts && !script_jobs.is_empty() {
        verify_scripts_pool(&script_jobs)?;
    }
    // Empty BatchParents → missing abs → Err (cold forbidden).
    let mut structural_pending = rbitcoin_query::OutPointSet::default();
    let mut mtp_cache = U32Map::default();
    let _ = structural_validate_spends(
        query,
        block,
        ctx,
        archived_tx_fks,
        &spends,
        fees,
        &mut structural_pending,
        &batch_parents,
        &mut mtp_cache,
        &FkMap::default(),
        &mut Vec::new(),
    )?;
    Ok(())
}

/// Whether assemble should probe durable spentness / maturity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AssembleMode {
    /// Resolve prevout content + build script jobs; skip durable spentness/maturity.
    Optimistic,
    /// Full connect (legacy one-shot): spentness + maturity during assemble.
    Full,
}

/// One non-coinbase tx ready for script/sig verification (prevouts already resolved).
///
/// Mainnet BIP16 exception block (never enforce P2SH redeem), Core `BIP16Exception`.
/// Height 170060 — pre-activation spends of HASH160/EQUAL as bare scripts.
pub(crate) const BIP16_EXCEPTION_MAINNET: [u8; 32] = [
    // little-endian display hash 00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22
    0x22, 0x9c, 0x4f, 0xac, 0x88, 0xba, 0xb1, 0x94, 0xeb, 0x08, 0xf1, 0xa5, 0x28, 0xcc, 0x30, 0x8d,
    0xed, 0x23, 0x97, 0xf4, 0xf4, 0xeb, 0x6e, 0x75, 0xdc, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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
    if height == 0 {
        return false;
    }
    // Modern Core buries P2SH: validation.cpp sets SCRIPT_VERIFY_P2SH on every
    // block except the named BIP16Exception (handled above). The historical
    // "prev MTP >= 2012-04-01" gate is gone — keeping it splits from Core on
    // regtest and any early-MTP chain (redeemScript never runs).
    let _ = (params, prev_mtp);
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

/// Script-verify job for one non-coinbase create.
///
/// Confirm assemble attaches the wire [`Arc<Block>`] (no tx deep-clone). `txid`
/// is the structure/plan hash so scripts can probe mempool preverified without
/// re-hashing.
pub struct ScriptCheckJob {
    /// Wire txid (assemble / [`Self::new`]); used for mempool preverified skip.
    pub(crate) txid: [u8; 32],
    pub(crate) prevouts: Vec<TxOut>,
    /// Owned (tests) or shared wire block + index (confirm path).
    pub(crate) tx: JobTx,
    /// BIP65 CLTV active (false → OP_CLTV is a no-op, matching pre-activation).
    pub(crate) bip65_active: bool,
    /// BIP112 CSV active (false → OP_CSV is a no-op, matching pre-activation).
    pub(crate) bip112_active: bool,
    /// BIP66 strict DER active (false → accept historical lax DER encodings).
    pub(crate) bip66_active: bool,
    /// BIP16 P2SH active (false → `OP_HASH160 … OP_EQUAL` is bare, not redeem).
    pub(crate) bip16_active: bool,
    /// BIP341/342 taproot active (false → v1 witness program is anyone-can-spend).
    pub(crate) taproot_active: bool,
    /// SCRIPT_VERIFY_MINIMALIF (standardness / fixture flag; TapScript always on).
    pub(crate) minimal_if: bool,
    /// SCRIPT_VERIFY_NULLFAIL.
    pub(crate) nullfail: bool,
    /// SCRIPT_VERIFY_LOW_S.
    pub(crate) low_s: bool,
    /// SCRIPT_VERIFY_STRICTENC.
    pub(crate) strictenc: bool,
    /// SCRIPT_VERIFY_NULLDUMMY (also implied by bip112 on mainnet).
    pub(crate) null_dummy: bool,
    /// SCRIPT_VERIFY_MINIMALDATA.
    pub(crate) minimal_data: bool,
    /// SCRIPT_VERIFY_WITNESS_PUBKEYTYPE: witness keys must be compressed.
    pub(crate) witness_pubkeytype: bool,
    /// SCRIPT_VERIFY_WITNESS active (fixture flag / post-segwit production).
    pub(crate) witness_active: bool,
    /// SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM.
    pub(crate) discourage_upgradable_witness: bool,
    /// SCRIPT_VERIFY_CONST_SCRIPTCODE: CODESEPARATOR + FindAndDelete hard-fail.
    pub(crate) const_scriptcode: bool,
    /// Lookup/structure `TxPrecompute`. Set on the confirm path; tests lazy-`from_tx`.
    pub(crate) pre: std::sync::OnceLock<JobPre>,
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
    pub fn new(
        prevouts: Vec<TxOut>,
        tx: Transaction,
        bip65_active: bool,
        bip112_active: bool,
        bip66_active: bool,
        bip16_active: bool,
        taproot_active: bool,
    ) -> Self {
        use bitcoin::hashes::Hash;
        let txid = tx.compute_txid().to_byte_array();
        Self::with_txid(
            txid,
            prevouts,
            tx,
            bip65_active,
            bip112_active,
            bip66_active,
            bip16_active,
            taproot_active,
        )
    }

    /// Owned-tx path (tests / benches / unit connect): reuse precomputed txid.
    #[inline]
    pub(crate) fn with_txid(
        txid: [u8; 32],
        prevouts: Vec<TxOut>,
        tx: Transaction,
        bip65_active: bool,
        bip112_active: bool,
        bip66_active: bool,
        bip16_active: bool,
        taproot_active: bool,
    ) -> Self {
        Self::from_parts(
            txid,
            prevouts,
            JobTx::owned(tx),
            bip65_active,
            bip112_active,
            bip66_active,
            bip16_active,
            taproot_active,
        )
    }

    /// Confirm assemble: share the wire [`Arc<Block>`] (no `Transaction` clone).
    #[inline]
    pub(crate) fn with_shared_tx(
        txid: [u8; 32],
        prevouts: Vec<TxOut>,
        block: Arc<Block>,
        tx_index: usize,
        bip65_active: bool,
        bip112_active: bool,
        bip66_active: bool,
        bip16_active: bool,
        taproot_active: bool,
    ) -> Self {
        Self::from_parts(
            txid,
            prevouts,
            JobTx::shared(block, tx_index),
            bip65_active,
            bip112_active,
            bip66_active,
            bip16_active,
            taproot_active,
        )
    }

    /// Single construction site for activation + production standardness defaults.
    #[inline]
    fn from_parts(
        txid: [u8; 32],
        prevouts: Vec<TxOut>,
        tx: JobTx,
        bip65_active: bool,
        bip112_active: bool,
        bip66_active: bool,
        bip16_active: bool,
        taproot_active: bool,
    ) -> Self {
        Self {
            txid,
            prevouts,
            tx,
            bip65_active,
            bip112_active,
            bip66_active,
            bip16_active,
            taproot_active,
            minimal_if: false,
            nullfail: false,
            low_s: false,
            strictenc: false,
            // Default overwritten by `with_segwit` from `segwit_active_at`.
            null_dummy: true,
            minimal_data: false,
            witness_pubkeytype: false,
            witness_active: true,
            discourage_upgradable_witness: false,
            const_scriptcode: false,
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
                &*self.tx,
            )))
        })
    }

    #[inline]
    pub(crate) fn pre(&self) -> &rbitcoin_query::TxPrecompute {
        match self.job_pre() {
            JobPre::Owned(a) => a.as_ref(),
            JobPre::Slice { slice, idx } => &slice[*idx],
        }
    }

    /// BIP141/147: NULLDUMMY + WITNESS rules follow `segwit` (not CSV).
    #[inline]
    pub(crate) fn with_segwit(mut self, segwit_active: bool) -> Self {
        self.null_dummy = segwit_active;
        self.witness_active = segwit_active;
        self
    }
}

/// Identity-hashed `txid → V` (assemble index / pack creates).
pub(crate) type TxidMap<V> = std::collections::HashMap<[u8; 32], V, BuildHasherDefault<TxidHasher>>;

/// Pack-local create fk by parent txid (not per-vout — fk is per tx).
pub(crate) type PendingCreates = TxidMap<rbitcoin_primitives::Fk>;

/// Block-local prevout path counts; flush to [`confirm_phase_stats`] once.
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
    fn flush(&self) {
        let add = |a: &std::sync::atomic::AtomicU64, v: u64| {
            if v > 0 {
                a.fetch_add(v, Ordering::Relaxed);
            }
        };
        add(&confirm_phase_stats::ASM_IN_N, self.in_n);
        add(&confirm_phase_stats::ASM_PREV_SAME_N, self.same_n);
        add(&confirm_phase_stats::ASM_PREV_BATCH_N, self.batch_n);
        add(&confirm_phase_stats::ASM_PREV_COLD_N, self.cold_n);
        add(
            &confirm_phase_stats::ASM_PREV_COLD_NULL_FK_N,
            self.cold_null_fk_n,
        );
        add(
            &confirm_phase_stats::ASM_PREV_COLD_NOT_PIN_N,
            self.cold_not_pin_n,
        );
        add(
            &confirm_phase_stats::ASM_PREV_COLD_TXID_MISMATCH_N,
            self.cold_txid_mismatch_n,
        );
        add(
            &confirm_phase_stats::ASM_PREV_COLD_VOUT_MISS_N,
            self.cold_vout_miss_n,
        );
    }
}

/// Sequential assemble: resolve prevout **content**, build script jobs, collect spends.
///
/// [`AssembleMode::Optimistic`] (confirm IBD path): no durable spentness / maturity /
/// BIP68 create-height resolution — those run in [`structural_validate_spends`] after
/// scripts (load must not walk create height per parent). Absolute nLockTime finality
/// (BIP113 MTP of prev block) still runs here — it only needs header MTP.
/// [`AssembleMode::Full`]: spentness + maturity + BIP68 during the walk (legacy).
///
/// `pending_spent`: pack-local double-spend (early reject before scripts).
/// `pending_creates`: pack-local `txid → create_fk` (not per-vout).
/// Same-block outs use `txid_index` (this block, `pj < ti`); meters flush
/// once per block (no per-input Instant / atomics).
///
/// Prevouts resolve from per-batch [`rbitcoin_query::BatchParents`] +
/// [`rbitcoin_query::SpendEdges`]. Optimistic miss is `invariant:` (no head recover).
///
/// Returns `(script_jobs, spends, fees)` — fees for coinbase subsidy check on structural.
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
        )>,
        i64,
    ),
    ConsensusError,
> {
    assemble_block_prevouts_mode(
        query,
        block,
        ctx,
        archived_tx_fks,
        pending_spent,
        pending_creates,
        AssembleMode::Optimistic,
        batch_parents,
        spend_edges,
        create_txids,
        prev_mtp,
        block_hash,
        bip16_active,
        wire,
        pres,
    )
}

fn assemble_block_prevouts_mode(
    query: &Query,
    block: &Block,
    ctx: &ValidationContext<'_>,
    archived_tx_fks: Option<&[rbitcoin_primitives::Fk]>,
    pending_spent: &mut rbitcoin_query::OutPointSet,
    pending_creates: &mut PendingCreates,
    mode: AssembleMode,
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
        )>,
        i64,
    ),
    ConsensusError,
> {
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
    // Caller-supplied BIP16 must match hash+prev_mtp (no silent re-resolve).
    debug_assert_eq!(
        bip16_active,
        bip16_active_from_prev_mtp(ctx.params, ctx.height.0, block_hash, prev_mtp)
    );
    let _ = block_hash; // used in debug_assert; release keeps caller contract
    let bip16_for_jobs = bip16_active;
    let flag_bip65 = ctx.params.bip65_active_at(ctx.height.0);
    let flag_csv = ctx.params.csv_active_at(ctx.height.0);
    let flag_bip66 = ctx.params.bip66_active_at(ctx.height.0);
    let flag_taproot = ctx.params.taproot_active_at(ctx.height.0);
    let flag_segwit = ctx.params.segwit_active_at(ctx.height.0);

    let n_tx = block.txdata.len();
    let mut txid_index: TxidMap<usize> =
        TxidMap::with_capacity_and_hasher(n_tx, Default::default());
    for (i, id) in create_txids.iter().enumerate() {
        txid_index.insert(*id, i);
    }
    let mut acc = AsmPrevoutAcc::default();
    let mut clk_prev = 0u64;
    let mut clk_sig = 0u64;
    let mut clk_fin = 0u64;
    let mut clk_job = 0u64;
    let mut fees = 0i64;
    let build_script_jobs = !ctx.milestone.skips_scripts_at(ctx.height.0);
    let mut script_jobs: Vec<ScriptCheckJob> = if build_script_jobs {
        Vec::with_capacity(n_tx.saturating_sub(1))
    } else {
        Vec::new()
    };
    const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;
    let mut block_sigops_cost = legacy_sigop_count(&block.txdata[0]).saturating_mul(4);
    let mut spends: Vec<(
        [u8; 32],
        u32,
        rbitcoin_primitives::Fk,
        rbitcoin_primitives::Fk,
    )> = Vec::with_capacity(n_tx.saturating_mul(2));
    let mut coinbase_height_cache: FkMap<Option<u32>> =
        FkMap::with_capacity_and_hasher(64, Default::default());

    use crate::confirm_phase_stats;
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    // BIP113: caller prev_mtp (same as header MTP — no second walk).
    let lock_time_cutoff = if ctx.params.csv_active_at(ctx.height.0) {
        if ctx.height.0 == 0 {
            block.header.time
        } else {
            prev_mtp
        }
    } else {
        block.header.time
    };

    for (ti, tx) in block.txdata.iter().enumerate() {
        let spend_fk = archived_tx_fks.map(|fks| fks[ti]);
        // Sole pipeline identity — structure/plan computed once; never re-hash here.
        let txid = create_txids[ti];

        if !is_final_tx(tx, ctx.height.0, lock_time_cutoff) {
            return Err(ConsensusError::BadTx("bad-txns-nonfinal"));
        }
        if tx.output.is_empty() {
            return Err(ConsensusError::BadTx("no outputs"));
        }
        if ti > 0 {
            if tx.input.is_empty() {
                return Err(ConsensusError::BadTx("no inputs"));
            }

            let mut value_in = 0i64;
            let mut prevouts: Vec<TxOut> = if build_script_jobs {
                Vec::with_capacity(tx.input.len())
            } else {
                Vec::new()
            };
            let mut input_create_heights: Vec<u32> = if mode == AssembleMode::Full {
                Vec::with_capacity(tx.input.len())
            } else {
                Vec::new()
            };
            let edges = spend_fk.and_then(|fk| fk.get().and_then(|id| spend_edges.get(&id)));
            let mut tx_in_sigops = 0u64;

            let t_prev = Instant::now();
            for (ii, input) in tx.input.iter().enumerate() {
                let op = input.previous_output;
                let key = (op.txid.to_byte_array(), op.vout);
                if !pending_spent.insert(key) {
                    return Err(ConsensusError::BadTx("double spend in block"));
                }
                // Same-block parent must appear *before* this tx. spend edges
                // stamp the whole block; using that edge accepts child-before-parent
                // (docs/external_findings/005-non-topological-block-accepted.md).
                if let Some(&pj) = txid_index.get(&key.0) {
                    if pj >= ti {
                        return Err(ConsensusError::MissingPrevout);
                    }
                }
                // Thin create_fk is a promise (identity matches wire prev_txid).
                // Do not treat thin as a soft spentness hint. Same-block (pj < ti)
                // resolves via same_block only.
                let prev_fk = edges
                    .as_ref()
                    .and_then(|t| t.get(ii))
                    .and_then(|e| e.create_fk.get().map(|_| e.create_fk))
                    .or_else(|| pending_creates.get(&key.0).copied())
                    .or_else(|| {
                        if mode == AssembleMode::Full {
                            query
                                .tx_fk_by_txid_tip(op.txid.as_byte_array())
                                .ok()
                                .flatten()
                        } else {
                            None
                        }
                    });
                let pin_live = match prev_fk {
                    Some(fk) if mode == AssembleMode::Full => {
                        batch_parents.has_parent_out(fk, op.vout)
                    }
                    _ => false,
                };
                // Durable spentness: Full mode only. Optimistic defers to structural
                // after scripts (assumevalid-shaped: scripts need values, not UTXO proof).
                if mode == AssembleMode::Full && !pin_live && !pending_creates.contains_key(&key.0)
                {
                    let spent = if let Some(cfk) = prev_fk {
                        query
                            .store()
                            .has_confirmed_strong_spender_create(cfk, op.vout, None)
                            .map_err(ConsensusError::from)?
                    } else {
                        query
                            .store()
                            .has_confirmed_strong_spender(op.txid.as_byte_array(), op.vout)
                            .map_err(ConsensusError::from)?
                    };
                    if spent {
                        return Err(ConsensusError::PrevoutSpent);
                    }
                }
                let prev_out = resolve_prevout(
                    query,
                    block,
                    op,
                    input,
                    prev_fk,
                    &txid_index,
                    ti,
                    &mut coinbase_height_cache,
                    batch_parents,
                    ctx.height.0,
                    mode == AssembleMode::Full,
                    bip16_for_jobs,
                    flag_segwit,
                    build_script_jobs,
                    &mut acc,
                )?;
                let create_fk = prev_out.create_fk;
                tx_in_sigops = tx_in_sigops.saturating_add(prev_out.input_sigops);
                if mode == AssembleMode::Full {
                    if let Some(created) = prev_out.coinbase_height {
                        let maturity = ctx.params.coinbase_maturity();
                        if ctx.height.0 < created.saturating_add(maturity) {
                            return Err(ConsensusError::BadTx("coinbase immature"));
                        }
                    }
                }
                spends.push((
                    key.0,
                    key.1,
                    spend_fk.unwrap_or(rbitcoin_primitives::Fk::NULL),
                    create_fk,
                ));
                value_in = value_in
                    .checked_add(prev_out.txout.value.to_sat() as i64)
                    .ok_or(ConsensusError::BadTx("value in overflow"))?;
                if mode == AssembleMode::Full {
                    input_create_heights.push(prev_out.create_height);
                }
                if build_script_jobs {
                    prevouts.push(prev_out.txout);
                }
            }
            clk_prev = clk_prev.saturating_add(t_prev.elapsed().as_nanos() as u64);

            let t_sig = Instant::now();
            block_sigops_cost = block_sigops_cost
                .saturating_add(legacy_sigop_count(tx).saturating_mul(4))
                .saturating_add(tx_in_sigops);
            if block_sigops_cost > MAX_BLOCK_SIGOPS_COST {
                return Err(ConsensusError::BadBlock("bad-blk-sigops"));
            }
            clk_sig = clk_sig.saturating_add(t_sig.elapsed().as_nanos() as u64);

            let t_fin = Instant::now();
            // Full mode only: Optimistic defers BIP68 to structural. Reuse BIP113 MTP.
            if mode == AssembleMode::Full && ctx.params.csv_active_at(ctx.height.0) {
                let mut coin_mtps = Vec::with_capacity(input_create_heights.len());
                for &ch in &input_create_heights {
                    let mtp = if ch == 0 {
                        0
                    } else {
                        crate::header::median_time_past(query, Height(ch.saturating_sub(1)))?
                    };
                    coin_mtps.push(mtp);
                }
                let prev_mtp = if ctx.height.0 == 0 {
                    0
                } else {
                    lock_time_cutoff
                };
                if !sequence_locks_satisfied(
                    tx,
                    &input_create_heights,
                    &coin_mtps,
                    ctx.height.0,
                    prev_mtp,
                ) {
                    return Err(ConsensusError::BadTx("bad-txns-nonfinal"));
                }
            }
            clk_fin = clk_fin.saturating_add(t_fin.elapsed().as_nanos() as u64);

            let mut value_out = 0i64;
            for o in &tx.output {
                let sats = o.value.to_sat() as i64;
                if sats < 0 {
                    return Err(ConsensusError::BadTx("negative output"));
                }
                value_out = value_out
                    .checked_add(sats)
                    .ok_or(ConsensusError::BadTx("value out overflow"))?;
            }
            if value_out > value_in {
                return Err(ConsensusError::BadTx("in < out"));
            }
            fees = fees
                .checked_add(value_in - value_out)
                .ok_or(ConsensusError::BadTx("fee overflow"))?;

            if build_script_jobs {
                let t_job = Instant::now();
                // Reuse A1 wire txid — scripts stage must not re-hash for preverified.
                let mut job = if let Some(w) = wire {
                    ScriptCheckJob::with_shared_tx(
                        txid,
                        prevouts,
                        Arc::clone(w),
                        ti,
                        flag_bip65,
                        flag_csv,
                        flag_bip66,
                        bip16_for_jobs,
                        flag_taproot,
                    )
                    .with_segwit(flag_segwit)
                } else {
                    ScriptCheckJob::with_txid(
                        txid,
                        prevouts,
                        tx.clone(),
                        flag_bip65,
                        flag_csv,
                        flag_bip66,
                        bip16_for_jobs,
                        flag_taproot,
                    )
                    .with_segwit(flag_segwit)
                };
                if let Some(ps) = pres {
                    if ti < ps.len() {
                        job = job.with_pre_slice(Arc::clone(ps), ti);
                    }
                }
                script_jobs.push(job);
                clk_job = clk_job.saturating_add(t_job.elapsed().as_nanos() as u64);
            }
        }

        let create_fk = spend_fk.unwrap_or(rbitcoin_primitives::Fk::NULL);
        if !create_fk.is_null() {
            pending_creates.insert(txid, create_fk);
        }
    }

    acc.flush();
    confirm_phase_stats::ASM_PREVOUT_NS.fetch_add(clk_prev, Ordering::Relaxed);
    confirm_phase_stats::ASM_SIGOP_NS.fetch_add(clk_sig, Ordering::Relaxed);
    confirm_phase_stats::ASM_FINAL_NS.fetch_add(clk_fin, Ordering::Relaxed);
    confirm_phase_stats::ASM_JOB_NS.fetch_add(clk_job, Ordering::Relaxed);
    Ok((script_jobs, spends, fees))
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
/// Write-path spend annotate: abs + structural meta, no pin `get_spender_abs`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SpendAnnotateJob {
    pub abs: u64,
    pub field: rbitcoin_primitives::Fk,
    pub flags: u8,
    pub create_fk: rbitcoin_primitives::Fk,
    pub vout: u32,
    pub spend_fk: rbitcoin_primitives::Fk,
}

/// **Spentness:** pin denserels → abs + bulk 8-byte meta. Sparse durable-**spent**
/// set (not unspent). Missing abs / short meta is hard `Err`. **Multi-list** after
/// reorg annotate is a protocol cold walk (`has_confirmed_strong_spender_create`)
/// — not a hard fail (tip-follow reorgs leave multi flags by design). Emits
/// [`SpendAnnotateJob`] for pure-write annotate.
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
    )],
    fees: i64,
    pending_spent: &mut rbitcoin_query::OutPointSet,
    batch_parents: &rbitcoin_query::BatchParents,
    mtp_cache: &mut U32Map<u32>,
    run_create_height: &FkMap<u32>,
    annotate: &mut Vec<SpendAnnotateJob>,
) -> Result<StructuralPhaseNs, ConsensusError> {
    use std::collections::HashSet;
    use std::time::Instant;

    let mut create_height_by_fk: FkMap<u32> =
        FkMap::with_capacity_and_hasher(spends.len().min(256), BuildHasherDefault::default());
    let maturity = ctx.params.coinbase_maturity();

    // BIP30: after BIP34, skipped. Before that, a connected instance with any
    // unspent output may not be overwritten — except mainnet 91842 / 91880.
    // Just-archived self is unconnected (not a hit); only a live sibling is.
    if !ctx.params.bip34_active_at(ctx.height.0)
        && !ctx.params.is_bip30_repeat(ctx.height.0, block.block_hash())
    {
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
            let rec = query.store().get_tx(old_fk).map_err(ConsensusError::from)?;
            let mut unspent = false;
            for v in 0..rec.output_count {
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
    }

    // On-disk spender meta is authority; pin only supplies abs. No cold body walk.
    let t_spent = Instant::now();

    // Every non-null create must have pin abs. Missing abs is a load bug —
    // not a soft cold spentness path.
    let t_abs = Instant::now();
    let abs_jobs = batch_parents
        .spend_abs_jobs(spends.iter().map(|&(_, vout, sfk, cfk)| (cfk, vout, sfk)))
        .map_err(ConsensusError::from)?;
    let unique_create_fks: Vec<rbitcoin_primitives::Fk> = {
        let mut v: Vec<rbitcoin_primitives::Fk> = abs_jobs
            .iter()
            .map(|(id, _, _, _)| rbitcoin_primitives::Fk(*id))
            .collect();
        v.sort_unstable_by_key(|f| f.0);
        v.dedup();
        v
    };
    let durable_heights = query
        .store()
        .tx_height_get_batch(&unique_create_fks)
        .map_err(ConsensusError::from)?;
    let height_by_id: U64Map<u32> = unique_create_fks
        .iter()
        .zip(durable_heights.into_iter())
        .filter_map(|(fk, h)| {
            let id = fk.get()?;
            let h = h.or_else(|| run_create_height.get(fk).copied())?;
            Some((id, h))
        })
        .collect();
    // Sparse durable **spent** set (honest IBD: almost all outs unspent).
    // Present ⇒ confirmed-strong spent; missing ⇒ unspent.
    let mut durable_spent: HashSet<(u64, u32)> = HashSet::new();
    let mut multi_list_ns = 0u64;

    let tip = query.tip_height().map(|h| h.0);

    let mut spent_strong_ns = 0u64;
    if !abs_jobs.is_empty() {
        let abs_offs: Vec<u64> = abs_jobs.iter().map(|(_, _, a, _)| *a).collect();
        let meta_backend = rbitcoin_store::spend_meta_backend();
        let t_meta = Instant::now();
        let metas = query
            .store()
            .get_spender_meta_at_abs_batch_backend(&abs_offs, meta_backend)
            .map_err(ConsensusError::from)?;
        let meta_ns = t_meta.elapsed().as_nanos() as u64;
        confirm_phase_stats::SPEND_META_NS.fetch_add(meta_ns, Ordering::Relaxed);
        confirm_phase_stats::SPEND_META_N.fetch_add(abs_offs.len() as u64, Ordering::Relaxed);
        let _ = meta_backend;
        if metas.len() != abs_jobs.len() {
            return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                "invariant: structural meta batch length",
            )));
        }
        let t_strong = Instant::now();
        let mut field_fks: Vec<rbitcoin_primitives::Fk> = Vec::new();
        let mut field_seen = rbitcoin_query::U64Set::default();
        for row in &metas {
            let Some((field, _)) = row else {
                continue;
            };
            if field.is_null() {
                continue;
            }
            if let Some(fid) = field.get() {
                if field_seen.insert(fid) {
                    field_fks.push(*field);
                }
            }
        }
        let field_heights = query
            .store()
            .tx_height_get_batch(&field_fks)
            .map_err(ConsensusError::from)?;
        let field_h_by_id: U64Map<u32> = field_fks
            .iter()
            .zip(field_heights.into_iter())
            .filter_map(|(fk, h)| Some((fk.get()?, h?)))
            .collect();
        for (i, &(id, vout, abs, sfk)) in abs_jobs.iter().enumerate() {
            let Some((field, flags)) = metas[i] else {
                return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                    "invariant: structural spender meta short/OOB (cold forbidden)",
                )));
            };
            annotate.push(SpendAnnotateJob {
                abs,
                field,
                flags,
                create_fk: rbitcoin_primitives::Fk(id),
                vout,
                spend_fk: sfk,
            });
            let multi = flags & rbitcoin_store::output_flags::MULTI_SPENDER != 0;
            if multi {
                // Protocol path (docs/invariants.md): reorg / second annotate leaves a
                // multi-list. Resolve confirmed-strong via list walk — do **not**
                // hard-fail the flag alone (that freezes tip after any tip-follow reorg
                // that double-annotated a parent out).
                let t_m = Instant::now();
                let spent = query
                    .store()
                    .has_confirmed_strong_spender_create(rbitcoin_primitives::Fk(id), vout, None)
                    .map_err(ConsensusError::from)?;
                multi_list_ns = multi_list_ns.saturating_add(t_m.elapsed().as_nanos() as u64);
                if spent {
                    durable_spent.insert((id, vout));
                }
                continue;
            }
            if field.is_null() {
                continue;
            }
            let strong = query
                .store()
                .is_confirmed_strong_at(field, tip)
                .map_err(ConsensusError::from)?;
            if !strong {
                continue;
            }
            // Integrity: a confirmed-strong spender cannot predate its create.
            // Prior tip-follow annotate bugs wrote garbage sole fields that point
            // at ancient strong fks (e.g. create@961404 / field@22671) — that is
            // not consensus PrevoutSpent. Ignore impossible meta (load/annotate
            // corruption), do not soft-recover via wire re-check.
            let create_h = height_by_id.get(&id).copied();
            let spend_h = field.get().and_then(|fid| field_h_by_id.get(&fid).copied());
            if let (Some(ch), Some(sh)) = (create_h, spend_h) {
                if sh < ch {
                    continue;
                }
            }
            durable_spent.insert((id, vout));
        }
        spent_strong_ns = t_strong
            .elapsed()
            .as_nanos()
            .saturating_sub(multi_list_ns as u128) as u64;
    }
    let spent_abs_ns = (t_abs.elapsed().as_nanos() as u64).saturating_sub(spent_strong_ns);

    // Null create_fk = same-block. Double-spend is only `pending_spent`.
    // Multi-list walks are the only "cold" spentness (protocol, not body).
    let spent_cold_ns = multi_list_ns;

    let t_pending = Instant::now();
    for &(prev_txid, vout, _spend_fk, create_fk) in spends {
        let key = (prev_txid, vout);
        if pending_spent.contains(&key) {
            return Err(ConsensusError::PrevoutSpent);
        }
        let spent = if create_fk.is_null() {
            false
        } else if let Some(id) = create_fk.get() {
            durable_spent.contains(&(id, vout))
        } else {
            false
        };
        if spent {
            return Err(ConsensusError::PrevoutSpent);
        }
        pending_spent.insert(key);
    }
    let spent_pending_ns = t_pending.elapsed().as_nanos() as u64;
    let spent_ns = t_spent.elapsed().as_nanos() as u64;

    // Coinbase = create_fk == first_tx_fk at that height — never `tx.body`.
    let t_create = Instant::now();
    let mut height_list: Vec<u32> = height_by_id.values().copied().collect();
    height_list.sort_unstable();
    height_list.dedup();
    let coinbase_fk_by_height = query
        .store()
        .coinbase_fk_at_heights(&height_list)
        .map_err(ConsensusError::from)?;

    for create_fk in &unique_create_fks {
        let Some(id) = create_fk.get() else {
            continue;
        };
        let Some(&durable_h) = height_by_id.get(&id) else {
            return Err(ConsensusError::BadTx("bad-txns-inputs-missingorspent"));
        };

        if batch_parents.get_parent_coinbase(*create_fk) == Some(false) {
            create_height_by_fk.insert(*create_fk, durable_h);
            continue;
        }

        let is_cb = batch_parents.get_parent_coinbase(*create_fk) == Some(true)
            || coinbase_fk_by_height
                .get(&durable_h)
                .is_some_and(|cb| *cb == *create_fk);
        if is_cb && ctx.height.0 < durable_h.saturating_add(maturity) {
            return Err(ConsensusError::BadTx("coinbase immature"));
        }
        create_height_by_fk.insert(*create_fk, durable_h);
    }
    let create_h_ns = t_create.elapsed().as_nanos() as u64;

    // v1 txs skip BIP68. Coin MTP only for time-type (TYPE_FLAG) relative locks.
    let t_bip68 = Instant::now();
    if ctx.params.csv_active_at(ctx.height.0) {
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
            for (inp, &(_ptid, _vout, _sfk, create_fk)) in tx.input.iter().zip(tx_spends.iter()) {
                let ch = if create_fk.is_null() {
                    // Same-block create (no Class A fk yet): Core uses spend height.
                    ctx.height.0
                } else {
                    create_height_by_fk.get(&create_fk).copied().unwrap_or(0)
                };
                prev_heights.push(ch);
                let seq = inp.sequence.to_consensus_u32();
                let need_mtp = seq & DISABLE == 0 && seq & TYPE_FLAG != 0;
                let mtp = if !need_mtp || ch == 0 {
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
    }
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

/// MTP for write structural. Prefers assemble-carried `prev_mtp` (seeded into
/// `cache`). Misses go to durable headers only — never `get_header_plan`.
fn mtp_at(query: &Query, height: Height, cache: &mut U32Map<u32>) -> Result<u32, ConsensusError> {
    if let Some(&t) = cache.get(&height.0) {
        return Ok(t);
    }
    let t = crate::header::median_time_past_store(query, height)?;
    cache.insert(height.0, t);
    Ok(t)
}

/// Parallel script checks for an owned job slice (preferred entry — no ref `Vec`).
///
/// Uses the in-crate [`crate::script_pool`] (not rayon). One job = one
/// non-coinbase tx (shared [`bitcoin::sighash::SighashCache`] across its inputs).
/// Pool threads (`rbtc-scripts-*`) steal jobs; the publisher does not wait on the pool.
pub fn verify_scripts_pool(jobs: &[ScriptCheckJob]) -> Result<(), ConsensusError> {
    crate::script_pool::try_for_each_parallel(jobs, verify_one_script_job)
}

/// Whether this job can skip `verify_job_all_inputs`.
///
/// OP_TRUE scriptPubKey alone is **not** sufficient: Core still
/// `EvalScript(scriptSig)` (CLTV/CSV may live there). Only skip when every
/// input is a pure ACS spend (empty scriptSig + empty witness + OP_TRUE spk).
#[inline]
fn job_needs_script_check(job: &ScriptCheckJob) -> bool {
    let tx: &bitcoin::Transaction = &*job.tx;
    for (i, prev) in job.prevouts.iter().enumerate() {
        if !is_anyone_can_spend(prev.script_pubkey.as_script()) {
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
    /// P2SH+witness sigop cost for this input's prevout script (not legacy).
    input_sigops: u64,
    /// `Some(create_height)` when prev is a confirmed coinbase (maturity check).
    coinbase_height: Option<u32>,
    /// Block height that created this UTXO (BIP68). Same-block → spending height.
    create_height: u32,
    /// Class A create fk for this prevout (or `NULL` for same-block). Load pin
    /// denserels must carry identity matching wire `prev_txid` for this fk.
    create_fk: rbitcoin_primitives::Fk,
}

/// BIP65/113 nLockTime threshold: values below are block heights, above are unix times.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// Core `IsFinalTx`: absolute locktime vs block height / time cutoff.
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
/// the creating block (for time-based locks; use 0 when create height is 0).
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
        // Missing/zero coin height is unresolved. Defaulting to 0 fails *open*
        // for time locks (epoch MTP). Same-block callers pass spend height — never 0.
        let Some(&coin_h) = prev_heights.get(i) else {
            return false;
        };
        if coin_h == 0 {
            return false;
        }
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

fn resolve_prevout(
    query: &Query,
    block: &Block,
    op: OutPoint,
    inp: &bitcoin::TxIn,
    prev_fk_hint: Option<rbitcoin_primitives::Fk>,
    txid_index: &TxidMap<usize>,
    spend_ti: usize,
    coinbase_height_cache: &mut FkMap<Option<u32>>,
    batch_parents: &rbitcoin_query::BatchParents,
    spend_height: u32,
    // Optimistic: prevout value/script only. BIP68 + maturity run in structural.
    resolve_create_heights: bool,
    bip16: bool,
    segwit: bool,
    need_script_buf: bool,
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
            return Ok(ResolvedPrevout {
                txout: o.clone(),
                input_sigops: prevout_spk_sigops(inp, o.script_pubkey.as_bytes(), bip16, segwit),
                coinbase_height: None,
                create_height: if resolve_create_heights {
                    spend_height
                } else {
                    0
                },
                create_fk: rbitcoin_primitives::Fk::NULL,
            });
        }
    }

    // Batch pin first (no TxRecord clone — A3). Cold Class A only when the
    // create is not pin-covered. Pin identity/vout misses are hard invariants
    // (load must fill schema-13 identity + denserels for need_vouts).
    // N1: classify warm-path miss so cold_n is explainable on `ibd: perf`.
    #[derive(Clone, Copy)]
    enum ColdWhy {
        NullFk,
        NotPin,
    }
    enum PinLook {
        Mismatch,
        Hit { txout: TxOut, input_sigops: u64 },
    }
    let mut cold_why = ColdWhy::NullFk;

    if let Some(prev_fk) = prev_fk_hint {
        cold_why = ColdWhy::NotPin;
        match batch_parents.get_parent_txout_parts(
            prev_fk,
            op.vout,
            |value, script, parent_txid| {
                if parent_txid != prev_txid {
                    return PinLook::Mismatch;
                }
                PinLook::Hit {
                    txout: TxOut {
                        value: Amount::from_sat(value as u64),
                        script_pubkey: if need_script_buf {
                            ScriptBuf::from_bytes(script.to_vec())
                        } else {
                            ScriptBuf::new()
                        },
                    },
                    input_sigops: prevout_spk_sigops(inp, script, bip16, segwit),
                }
            },
        ) {
            Some(PinLook::Hit {
                txout,
                input_sigops,
            }) => {
                let (cb_h, create_height) = if resolve_create_heights {
                    let prev_rec = batch_parents
                        .get_parent_tx(prev_fk)
                        .ok_or(ConsensusError::MissingPrevout)?;
                    let cb_h = coinbase_height_for_maturity(
                        query,
                        prev_fk,
                        &prev_rec,
                        batch_parents,
                        coinbase_height_cache,
                    )?;
                    (cb_h, create_height_for_fk(query, prev_fk, cb_h)?)
                } else {
                    (None, 0)
                };
                acc.in_n = acc.in_n.saturating_add(1);
                acc.batch_n = acc.batch_n.saturating_add(1);
                #[cfg(test)]
                confirm_phase_stats::tl_note_batch_hit();
                return Ok(ResolvedPrevout {
                    txout,
                    input_sigops,
                    coinbase_height: cb_h,
                    create_height,
                    create_fk: prev_fk,
                });
            }
            Some(PinLook::Mismatch) => {
                acc.cold_txid_mismatch_n = acc.cold_txid_mismatch_n.saturating_add(1);
                #[cfg(test)]
                confirm_phase_stats::tl_note_cold_why_txid_mismatch();
                return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                    "invariant: pin parent create identity mismatch wire prev_txid",
                )));
            }
            None if batch_parents.contains(prev_fk) => {
                acc.cold_vout_miss_n = acc.cold_vout_miss_n.saturating_add(1);
                #[cfg(test)]
                confirm_phase_stats::tl_note_cold_why_vout_miss();
                return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                    "invariant: pin incomplete outs for spent parent vout",
                )));
            }
            None => {}
        }
    }

    if !resolve_create_heights {
        return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
            "invariant: lookup stage miss (assemble parent create_fk)",
        )));
    }
    let head_fk = query
        .tx_fk_by_txid_tip(&prev_txid)
        .map_err(ConsensusError::from)?;
    let candidates = [prev_fk_hint, head_fk];
    let mut seen: [u64; 3] = [0; 3];
    let mut n_seen = 0usize;
    for prev_fk in candidates.into_iter().flatten() {
        if prev_fk.is_null() {
            continue;
        }
        let id = prev_fk.0;
        if seen[..n_seen].contains(&id) {
            continue;
        }
        if n_seen < 3 {
            seen[n_seen] = id;
            n_seen += 1;
        }
        let prev_rec = match query.get_tx_class_a(prev_fk) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if prev_rec.txid != prev_txid {
            continue;
        }
        let out = match find_output(query, prev_fk, &prev_rec, op.vout) {
            Ok(o) => o,
            Err(ConsensusError::MissingPrevout) => continue,
            Err(e) => return Err(e),
        };
        let (cb_h, create_height) = if resolve_create_heights {
            let cb_h = coinbase_height_for_maturity(
                query,
                prev_fk,
                &prev_rec,
                batch_parents,
                coinbase_height_cache,
            )?;
            (cb_h, create_height_for_fk(query, prev_fk, cb_h)?)
        } else {
            (None, 0)
        };
        acc.in_n = acc.in_n.saturating_add(1);
        acc.cold_n = acc.cold_n.saturating_add(1);
        match cold_why {
            ColdWhy::NullFk => {
                acc.cold_null_fk_n = acc.cold_null_fk_n.saturating_add(1);
                #[cfg(test)]
                confirm_phase_stats::tl_note_cold_why_null_fk();
            }
            ColdWhy::NotPin => {
                acc.cold_not_pin_n = acc.cold_not_pin_n.saturating_add(1);
                #[cfg(test)]
                confirm_phase_stats::tl_note_cold_why_not_pin();
            }
        }
        let input_sigops = prevout_spk_sigops(inp, &out.script, bip16, segwit);
        return Ok(ResolvedPrevout {
            txout: TxOut {
                value: Amount::from_sat(out.value as u64),
                script_pubkey: ScriptBuf::from_bytes(out.script),
            },
            input_sigops,
            coinbase_height: cb_h,
            create_height,
            create_fk: prev_fk,
        });
    }

    Err(ConsensusError::MissingPrevout)
}

/// Height of the block that created `prev_fk` (for BIP68).
fn create_height_for_fk(
    query: &Query,
    prev_fk: rbitcoin_primitives::Fk,
    coinbase_height: Option<u32>,
) -> Result<u32, ConsensusError> {
    if let Some(h) = coinbase_height {
        return Ok(h);
    }
    Ok(query
        .store()
        .tx_height_get(prev_fk)
        .map_err(ConsensusError::from)?
        .unwrap_or(0))
}

/// Coinbase create height for maturity, or `None` if not a coinbase / unknown.
///
/// Unlike the old `!is_cb || cb_h.is_some()` gate, a missing height never
/// discards an already-located parent output (that became MissingPrevout).
fn coinbase_height_for_maturity(
    query: &Query,
    prev_fk: rbitcoin_primitives::Fk,
    prev_rec: &rbitcoin_store::TxRecord,
    batch_parents: &rbitcoin_query::BatchParents,
    coinbase_height_cache: &mut FkMap<Option<u32>>,
) -> Result<Option<u32>, ConsensusError> {
    let (is_cb, cb_h) = coinbase_info(
        query,
        prev_fk,
        prev_rec,
        batch_parents,
        coinbase_height_cache,
    )?;
    if !is_cb {
        return Ok(None);
    }
    if cb_h.is_some() {
        return Ok(cb_h);
    }
    Ok(query
        .store()
        .tx_height_get(prev_fk)
        .map_err(ConsensusError::from)?)
}

/// `(is_coinbase, create_height if coinbase and confirmed)`.
fn coinbase_info(
    query: &Query,
    prev_fk: rbitcoin_primitives::Fk,
    prev_rec: &rbitcoin_store::TxRecord,
    batch_parents: &rbitcoin_query::BatchParents,
    cache: &mut FkMap<Option<u32>>,
) -> Result<(bool, Option<u32>), ConsensusError> {
    if let Some(&h) = cache.get(&prev_fk) {
        // Cache value is coinbase create height only: `Some(h)` ⇒ coinbase,
        // `None` ⇒ not a coinbase. Do **not** re-derive is_cb from
        // `input_count == 1` — single-input non-coinbases also cache `None`,
        // and that wrong is_cb made resolve fall through (MissingPrevout) on
        // the second spend of the same parent (mainnet @546: two vouts of one
        // 1-in parent in one spending tx).
        return Ok((h.is_some(), h));
    }
    // Batch pin may stash coinbase *flag* only (heights from durable Class C).
    if let Some(is_cb) = batch_parents.get_parent_coinbase(prev_fk) {
        if !is_cb {
            cache.insert(prev_fk, None);
            return Ok((false, None));
        }
        let h = query
            .store()
            .tx_height_get(prev_fk)
            .map_err(ConsensusError::from)?;
        if h.is_some() {
            cache.insert(prev_fk, h);
        }
        return Ok((true, h));
    }
    if prev_rec.input_count != 1 {
        cache.insert(prev_fk, None);
        return Ok((false, None));
    }
    let is_cb = is_coinbase_tx_record(query, prev_fk, prev_rec)?;
    let h = if is_cb {
        query
            .store()
            .tx_height_get(prev_fk)
            .map_err(ConsensusError::from)?
    } else {
        None
    };
    if !is_cb || h.is_some() {
        cache.insert(prev_fk, h);
    }
    Ok((is_cb, h))
}

fn is_coinbase_tx_record(
    query: &Query,
    prev_fk: rbitcoin_primitives::Fk,
    rec: &rbitcoin_store::TxRecord,
) -> Result<bool, ConsensusError> {
    if rec.input_count != 1 {
        return Ok(false);
    }
    // Key by create fk so packed Class A works with `tx.head` off (catch-up).
    let inp = query
        .tx_input_at_fk(prev_fk, rec, 0)
        .map_err(ConsensusError::from)?;
    Ok(inp.is_coinbase() || (inp.prev_txid == [0u8; 32] && inp.prev_index == 0xffff_ffff))
}

fn find_output(
    query: &Query,
    prev_fk: rbitcoin_primitives::Fk,
    prev_rec: &rbitcoin_store::TxRecord,
    vout: u32,
) -> Result<rbitcoin_store::OutputRecord, ConsensusError> {
    if vout >= prev_rec.output_count {
        return Err(ConsensusError::MissingPrevout);
    }
    query
        .tx_output_at_fk(prev_fk, vout)
        .map_err(ConsensusError::from)
}

fn is_anyone_can_spend(script: &Script) -> bool {
    crate::script::is_anyone_can_spend(script)
}

pub use rbitcoin_query::TxPrecompute;

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
mod tx_precompute;
