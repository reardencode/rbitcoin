//! Fast regtest empty-block pad (maturity) for tests in dependent crates.
//!
//! Prefer this over a local `for h in 1..=100 { mine_pow; connect }` loop.

use crate::block::apply_witness_commitment;
use crate::{bip34_height_script, block_has_witness, block_subsidy, ChainParams};
use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Target, Transaction,
    TxIn, TxMerkleNode, TxOut, Witness,
};

pub const REGTEST_POW_BITS: u32 = 0x207f_ffff;
pub const REGTEST_BLOCK_SPACING: u32 = 600;

/// Grind `header.nonce` until PoW matches `header.bits`. Does not change version.
///
/// Regtest bits (`0x207fffff`) hit in the first few nonces. An `OP_TRUE`
/// signet keeps genesis bits (`0x1e0377ae`), about 5e6 hashes. Past the
/// trivial prefix the search reuses the SHA256 midstate of the first 64
/// header bytes. Off the `tip-accept` thread that search uses up to four
/// cores; on `tip-accept` it stays on one core so the lane cannot join
/// workers that wait for the lane.
pub fn grind_regtest_pow(header: &mut Header) {
    assert!(try_grind_regtest_pow(header), "regtest pow grind exhausted");
}

/// [`grind_regtest_pow`] that reports a miss instead of panicking.
///
/// One nonce span is 2^32 hashes. A target more than 2^31 times harder than
/// `pow_limit` is a miss up front, so `generatetoaddress` can return an error
/// without scanning.
pub fn try_grind_regtest_pow(header: &mut Header) -> bool {
    let limit = crate::ChainParams::regtest().pow_limit;
    if !regtest_grind_fits_one_nonce_span(header.bits, limit) {
        return false;
    }
    let target = Target::from_compact(header.bits);
    const QUICK: u32 = 4096;
    for nonce in 0..QUICK {
        header.nonce = nonce;
        if header.validate_pow(target).is_ok() {
            return true;
        }
    }
    let Some(nonce) = grind_header_midstate(header, target, QUICK) else {
        return false;
    };
    header.nonce = nonce;
    debug_assert!(header.validate_pow(target).is_ok());
    true
}

/// `true` when one nonce span is expected to hit `bits`.
///
/// The ratio of `pow_limit` to the target is at most 2^31. Compared in the
/// compact exponent (8 bits per step) and the 23-bit mantissa.
#[doc(hidden)]
pub fn regtest_grind_fits_one_nonce_span(bits: CompactTarget, pow_limit: Target) -> bool {
    let limit = pow_limit.to_compact_lossy().to_consensus();
    let got = bits.to_consensus();
    let sign = 1u32 << 23;
    let limit_mant = u64::from(limit & (sign - 1));
    let got_mant = u64::from(got & (sign - 1));
    if limit_mant == 0 || got_mant == 0 {
        return false;
    }
    let limit_exp = limit >> 24;
    let got_exp = got >> 24;
    if got_exp > limit_exp {
        return true;
    }
    let delta = limit_exp - got_exp;
    if delta >= 8 {
        return false;
    }
    let left = limit_mant << (8 * delta);
    let right = got_mant << 31;
    left <= right
}

#[doc(hidden)]
pub fn on_tip_accept_thread() -> bool {
    std::thread::current().name() == Some("tip-accept")
}

/// SHA256 midstate after the first 64 header bytes. Nonce is the last 4
/// bytes. No heap per nonce.
#[doc(hidden)]
pub fn grind_header_midstate(header: &Header, target: Target, start: u32) -> Option<u32> {
    use bitcoin::consensus::Encodable;

    let mut raw = Vec::with_capacity(80);
    header
        .consensus_encode(&mut raw)
        .expect("header encode into vec");
    debug_assert_eq!(raw.len(), 80);
    let workers = if on_tip_accept_thread() {
        1
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, 4)
    };
    if workers == 1 {
        return grind_header_midstate_one(&raw, target, start, 1, None);
    }
    let stop = std::sync::atomic::AtomicBool::new(false);
    let hit = std::sync::atomic::AtomicBool::new(false);
    let found = std::sync::atomic::AtomicU32::new(u32::MAX);
    std::thread::scope(|scope| {
        for worker in 0..workers {
            let raw = &raw;
            let stop = &stop;
            let hit = &hit;
            let found = &found;
            let begin = start.saturating_add(worker as u32);
            scope.spawn(move || {
                if let Some(nonce) =
                    grind_header_midstate_one(raw, target, begin, workers as u32, Some(stop))
                {
                    found.fetch_min(nonce, std::sync::atomic::Ordering::Relaxed);
                    hit.store(true, std::sync::atomic::Ordering::Relaxed);
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            });
        }
    });
    if !hit.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }
    Some(found.load(std::sync::atomic::Ordering::Relaxed))
}

/// Search `start, start+step, …`. `step == 1` is the single-core scan.
///
/// `stop` lets sibling cores abandon the search once any stride has a hit.
/// Any nonce that meets `target` is a valid block; the caller keeps the
/// smallest one that was stored.
#[doc(hidden)]
pub fn grind_header_midstate_one(
    raw: &[u8],
    target: Target,
    start: u32,
    step: u32,
    stop: Option<&std::sync::atomic::AtomicBool>,
) -> Option<u32> {
    use bitcoin::hashes::{sha256, Hash, HashEngine};

    debug_assert!(step >= 1);
    let mut engine = sha256::Hash::engine();
    engine.input(&raw[..64]);
    let mid = engine.midstate();
    let mut tail = [0u8; 16];
    tail.copy_from_slice(&raw[64..80]);
    let mut nonce = start;
    let mut spins: u32 = 0;
    loop {
        if spins == 0 && stop.is_some_and(|s| s.load(std::sync::atomic::Ordering::Relaxed)) {
            return None;
        }
        spins = spins.wrapping_add(1) % 1024;
        tail[12..16].copy_from_slice(&nonce.to_le_bytes());
        let mut second = sha256::HashEngine::from_midstate(mid, 64);
        second.input(&tail);
        let first = sha256::Hash::from_engine(second);
        let pow = sha256::Hash::hash(first.as_byte_array());
        let hash = bitcoin::BlockHash::from_byte_array(pow.to_byte_array());
        if target.is_met_by(hash) {
            return Some(nonce);
        }
        nonce = nonce.checked_add(step)?;
    }
}

/// Fuzzer / tests keep txdata + version. Harness owns prev/bits/time/merkle/nonce.
pub fn prepare_regtest_candidate(block: &mut Block, prev: BlockHash, time: u32) {
    block.header.prev_blockhash = prev;
    block.header.bits = CompactTarget::from_consensus(REGTEST_POW_BITS);
    block.header.time = time;
    block.header.merkle_root = block
        .compute_merkle_root()
        .unwrap_or(TxMerkleNode::from_byte_array([0u8; 32]));
    grind_regtest_pow(&mut block.header);
}

/// Mine one empty-ish regtest block (trivial bits).
pub fn mine_empty_regtest(prev: BlockHash, time: u32, height: u32) -> Block {
    mine_regtest_paying(
        prev,
        time,
        height,
        ScriptBuf::from_bytes(vec![rbitcoin_primitives::OP_TRUE]),
        Vec::new(),
    )
}

/// Mine one regtest block paying `script_pubkey`, optional extra txs, trivial bits.
///
/// Adds a BIP141 witness commitment when any input carries witness data.
/// Confirm still goes through the normal accept/connect path (caller).
pub fn mine_regtest_paying(
    prev: BlockHash,
    time: u32,
    height: u32,
    script_pubkey: ScriptBuf,
    extra_txs: Vec<Transaction>,
) -> Block {
    mine_regtest_paying_bits(
        prev,
        time,
        height,
        script_pubkey,
        extra_txs,
        CompactTarget::from_consensus(REGTEST_POW_BITS),
    )
}

/// [`mine_regtest_paying_bits`] that returns an error when the nonce span misses.
pub fn try_mine_regtest_paying_bits(
    prev: BlockHash,
    time: u32,
    height: u32,
    script_pubkey: ScriptBuf,
    extra_txs: Vec<Transaction>,
    bits: CompactTarget,
) -> Result<Block, &'static str> {
    let mut block =
        assemble_regtest_paying_bits(prev, time, height, script_pubkey, extra_txs, bits);
    if !try_grind_regtest_pow(&mut block.header) {
        return Err("regtest pow grind exhausted");
    }
    Ok(block)
}

/// [`mine_regtest_paying`] at caller-chosen `bits` (the next-work result).
pub fn mine_regtest_paying_bits(
    prev: BlockHash,
    time: u32,
    height: u32,
    script_pubkey: ScriptBuf,
    extra_txs: Vec<Transaction>,
    bits: CompactTarget,
) -> Block {
    try_mine_regtest_paying_bits(prev, time, height, script_pubkey, extra_txs, bits)
        .expect("regtest pow grind exhausted")
}

fn assemble_regtest_paying_bits(
    prev: BlockHash,
    time: u32,
    height: u32,
    script_pubkey: ScriptBuf,
    extra_txs: Vec<Transaction>,
    bits: CompactTarget,
) -> Block {
    // Post-BIP65 (regtest height 1) requires nVersion ≥ 4. Core generate uses
    // VERSIONBITS_TOP_BITS; 4 is the buried minimum and enough for dersig/cltv.
    let header = Header {
        version: Version::from_consensus(4),
        prev_blockhash: prev,
        merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
        time,
        bits,
        nonce: 0,
    };
    let mut txdata = Vec::with_capacity(1 + extra_txs.len());
    txdata.push(coinbase_paying(height, script_pubkey));
    txdata.extend(extra_txs);
    let mut block = Block { header, txdata };
    if block_has_witness(&block) {
        apply_witness_commitment(&mut block);
    } else if let Some(root) = block.compute_merkle_root() {
        block.header.merkle_root = root;
    }
    block
}

/// One signet block whose challenge is `OP_TRUE`.
///
/// Bits come from the caller (the parent header at height 1). The coinbase
/// witness commitment carries an empty scriptSig / empty witness solution,
/// which is the only solution `OP_TRUE` accepts. PoW is a nonce grind against
/// signet's genesis target (`0x1e0377ae`, about 5e6 hashes, not regtest's
/// `0x207fffff`).
pub fn mine_op_true_signet_paying(
    params: &ChainParams,
    prev: BlockHash,
    time: u32,
    height: u32,
    bits: CompactTarget,
    script_pubkey: ScriptBuf,
    extra_txs: Vec<Transaction>,
) -> Block {
    let header = Header {
        version: Version::from_consensus(4),
        prev_blockhash: prev,
        merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
        time,
        bits,
        nonce: 0,
    };
    let mut txdata = Vec::with_capacity(1 + extra_txs.len());
    txdata.push(coinbase_paying_params(height, script_pubkey, params));
    txdata.extend(extra_txs);
    let mut block = Block { header, txdata };
    block.txdata[0].input[0].witness = Witness::from_slice(&[vec![0u8; 32]]);
    apply_witness_commitment(&mut block);
    append_op_true_signet_push(&mut block);
    grind_regtest_pow(&mut block.header);
    block
}

/// BIP325: second push in the witness-commitment script is header `ecc7daa2`
/// plus an empty scriptSig and an empty witness (`0x00 0x00`).
#[doc(hidden)]
pub fn append_op_true_signet_push(block: &mut Block) {
    const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];
    let mut payload = Vec::with_capacity(6);
    payload.extend_from_slice(&SIGNET_HEADER);
    payload.extend_from_slice(&[0x00, 0x00]);
    let spk = &mut block.txdata[0]
        .output
        .last_mut()
        .expect("witness commitment output")
        .script_pubkey;
    let mut bytes = spk.as_bytes().to_vec();
    bytes.push(u8::try_from(payload.len()).expect("signet solution push"));
    bytes.extend_from_slice(&payload);
    *spk = ScriptBuf::from_bytes(bytes);
    if let Some(root) = block.compute_merkle_root() {
        block.header.merkle_root = root;
    }
}

#[doc(hidden)]
pub fn coinbase_paying(height: u32, script_pubkey: ScriptBuf) -> Transaction {
    coinbase_paying_params(height, script_pubkey, &ChainParams::regtest())
}

#[doc(hidden)]
pub fn coinbase_paying_params(
    height: u32,
    script_pubkey: ScriptBuf,
    params: &ChainParams,
) -> Transaction {
    regtest_coinbase(
        height,
        Amount::from_sat(block_subsidy(height, params) as u64),
        script_pubkey,
    )
}

/// BIP34 coinbase (scriptSig padded to at least 2 bytes) paying `value` to `script_pubkey`.
pub fn regtest_coinbase(height: u32, value: Amount, script_pubkey: ScriptBuf) -> Transaction {
    let mut ss = if height == 0 {
        vec![rbitcoin_primitives::OP_0]
    } else {
        bip34_height_script(height)
    };
    while ss.len() < 2 {
        ss.push(rbitcoin_primitives::OP_0);
    }
    Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(ss),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey,
        }],
    }
}
