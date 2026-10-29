//! BIP325 signet consensus: every non-genesis tip block must satisfy the network challenge.
//!
//! Solution is embedded in the coinbase witness-commitment push after magic `ecc7daa2`.
//!
//! **When:** tip confirm / connect only — not Class A archive structure (ECDSA is too
//! expensive for the IBD prep path).

use bitcoin::absolute::LockTime;
use bitcoin::consensus::{serialize, Encodable};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::script::{Script, ScriptBuf};
use bitcoin::{Amount, Block, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::block::ScriptCheckJob;
use crate::error::ConsensusError;

/// BIP325 magic prefix inside the witness commitment push.
#[doc(hidden)]
pub const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];

/// Default global signet challenge (Bitcoin Core `SigNetParams` without `-signetchallenge`).
///
/// `OP_1 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG` (1-of-2).
pub fn default_signet_challenge() -> ScriptBuf {
    ScriptBuf::from_bytes(
        rbitcoin_primitives::hex_decode("512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae",)
        .expect("hex"),
    )
}

/// Derive the four P2P message-start bytes for a BIP325 challenge.
///
/// Bitcoin Core hashes the consensus-serialized challenge byte vector, including
/// its CompactSize length prefix, and uses the first four digest bytes.
pub fn signet_magic(challenge: &Script) -> [u8; 4] {
    let encoded = serialize(&challenge.as_bytes().to_vec());
    sha256d::Hash::hash(&encoded).to_byte_array()[..4]
        .try_into()
        .expect("four-byte digest prefix")
}

/// Validate BIP325 signet block solution against `challenge`.
pub fn validate_signet_block_solution(
    block: &Block,
    challenge: &Script,
) -> Result<(), ConsensusError> {
    if block.header.prev_blockhash.to_byte_array() == [0u8; 32] {
        return Ok(());
    }

    let (to_spend, to_sign) = match signet_challenge_transactions(block, challenge) {
        Ok(pair) => pair,
        Err(e) => {
            // Parse faults are warn-and-apply. `soften_at` keeps the hard
            // errors (`signet encode`) and returns them when no collector is open.
            crate::trust::soften_at(None, e)?;
            return Ok(());
        }
    };
    verify_challenge_spend(&to_spend, &to_sign, challenge)
}

/// BIP325 `to_spend` / `to_sign` pair. The challenge script is `to_sign`'s prevout.
pub fn signet_challenge_transactions(
    block: &Block,
    challenge: &Script,
) -> Result<(Transaction, Transaction), ConsensusError> {
    if block.txdata.is_empty() {
        return Err(ConsensusError::BadBlock("signet: no coinbase"));
    }

    let mut modified_cb = block.txdata[0].clone();
    let cidx = witness_commitment_index(&modified_cb)
        .ok_or(ConsensusError::BadBlock("signet: no witness commitment"))?;

    // Core: a missing SIGNET_HEADER section leaves the commitment as is and spends the
    // challenge with an empty scriptSig and witness; the challenge script decides.
    let (script_sig, witness) =
        match fetch_and_clear_signet_section(modified_cb.output[cidx].script_pubkey.as_bytes()) {
            Some((solution, stripped)) => {
                modified_cb.output[cidx].script_pubkey = ScriptBuf::from_bytes(stripped);
                parse_signet_solution(&solution)?
            }
            None => (ScriptBuf::new(), Witness::new()),
        };

    let signet_merkle = modified_merkle_root(&modified_cb, block)?;

    let mut block_data = Vec::new();
    block
        .header
        .version
        .to_consensus()
        .consensus_encode(&mut block_data)
        .map_err(|_| ConsensusError::BadBlock("signet encode"))?;
    block
        .header
        .prev_blockhash
        .consensus_encode(&mut block_data)
        .map_err(|_| ConsensusError::BadBlock("signet encode"))?;
    signet_merkle
        .consensus_encode(&mut block_data)
        .map_err(|_| ConsensusError::BadBlock("signet encode"))?;
    block
        .header
        .time
        .consensus_encode(&mut block_data)
        .map_err(|_| ConsensusError::BadBlock("signet encode"))?;

    // Core: `vin.emplace_back(COutPoint(), CScript(OP_0), 0)` then `scriptSig << block_data`.
    // scriptSig must be OP_0 + push(block_data) or the to_spend txid (and sighash) is wrong.
    let mut ss = vec![rbitcoin_primitives::OP_0];
    crate::script::interpreter::encode_push(&mut ss, &block_data);
    let to_spend = Transaction {
        version: bitcoin::transaction::Version::non_standard(0),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(ss),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(challenge.as_bytes().to_vec()),
        }],
    };
    let to_spend_txid = to_spend.compute_txid();

    let to_sign = Transaction {
        version: bitcoin::transaction::Version::non_standard(0),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: to_spend_txid,
                vout: 0,
            },
            script_sig,
            sequence: Sequence::ZERO,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![rbitcoin_primitives::OP_RETURN]),
        }],
    };

    Ok((to_spend, to_sign))
}

#[doc(hidden)]
pub fn witness_commitment_index(coinbase: &Transaction) -> Option<usize> {
    crate::block::witness_commitment_vout_index(coinbase)
}

/// Core `GetScriptOp`: the opcode at `pc` and its push payload (empty for a non-push).
/// `None` at the end of the script or on a truncated push.
#[doc(hidden)]
pub fn next_script_op<'a>(spk: &'a [u8], pc: &mut usize) -> Option<(u8, &'a [u8])> {
    let op = *spk.get(*pc)?;
    let mut at = *pc + 1;
    let len = match op {
        1..=rbitcoin_primitives::OP_PUSHBYTES_75 => usize::from(op),
        rbitcoin_primitives::OP_PUSHDATA1 => {
            let n = *spk.get(at)?;
            at += 1;
            usize::from(n)
        }
        rbitcoin_primitives::OP_PUSHDATA2 => {
            let n = spk.get(at..at + 2)?;
            at += 2;
            usize::from(u16::from_le_bytes([n[0], n[1]]))
        }
        rbitcoin_primitives::OP_PUSHDATA4 => {
            let n = spk.get(at..at + 4)?;
            at += 4;
            usize::try_from(u32::from_le_bytes([n[0], n[1], n[2], n[3]])).ok()?
        }
        _ => 0,
    };
    let end = at.checked_add(len)?;
    let data = spk.get(at..end)?;
    *pc = end;
    Some((op, data))
}

/// Core `FetchAndClearCommitmentSection`: take the payload after SIGNET_HEADER from the
/// first push that holds the header and some data; return (solution, rewritten script).
///
/// The rewrite stops at a truncated push. An empty push (OP_0 or a zero-length
/// PUSHDATA1/2/4) is re-emitted as its bare opcode, and a non-empty push through
/// [`crate::script::interpreter::encode_push`], so the modified coinbase txid matches Core.
#[doc(hidden)]
pub fn fetch_and_clear_signet_section(spk: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut pc = 0usize;
    let mut solution: Option<Vec<u8>> = None;
    let mut replacement = Vec::with_capacity(spk.len());

    while let Some((op, data)) = next_script_op(spk, &mut pc) {
        if data.is_empty() {
            replacement.push(op);
            continue;
        }
        if solution.is_none() {
            if let Some(sol) = extract_header_payload(data) {
                solution = Some(sol);
                crate::script::interpreter::encode_push(&mut replacement, &SIGNET_HEADER);
                continue;
            }
        }
        crate::script::interpreter::encode_push(&mut replacement, data);
    }

    solution.map(|sol| (sol, replacement))
}

#[doc(hidden)]
pub fn extract_header_payload(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() > SIGNET_HEADER.len() && data.starts_with(&SIGNET_HEADER) {
        Some(data[SIGNET_HEADER.len()..].to_vec())
    } else {
        None
    }
}

#[doc(hidden)]
pub fn parse_signet_solution(solution: &[u8]) -> Result<(ScriptBuf, Witness), ConsensusError> {
    let mut rdr = solution;
    let script_sig = read_script(&mut rdr)?;
    let witness = read_witness_stack(&mut rdr)?;
    if !rdr.is_empty() {
        return Err(ConsensusError::BadBlock("signet: extraneous solution data"));
    }
    Ok((script_sig, witness))
}

#[doc(hidden)]
pub fn read_signet_compact(rdr: &mut &[u8]) -> Result<u64, ConsensusError> {
    if rdr.is_empty() {
        return Err(ConsensusError::BadBlock("signet: compact size"));
    }
    let (v, n) = match rdr[0] {
        tag @ 0..=252 => (u64::from(tag), 1usize),
        253 => {
            if rdr.len() < 3 {
                return Err(ConsensusError::BadBlock("signet: compact size"));
            }
            let v = u16::from_le_bytes([rdr[1], rdr[2]]);
            if v < 253 {
                return Err(ConsensusError::BadBlock("signet: non-minimal compact size"));
            }
            (u64::from(v), 3)
        }
        254 => {
            if rdr.len() < 5 {
                return Err(ConsensusError::BadBlock("signet: compact size"));
            }
            let v = u32::from_le_bytes(rdr[1..5].try_into().expect("4 bytes"));
            if v <= u32::from(u16::MAX) {
                return Err(ConsensusError::BadBlock("signet: non-minimal compact size"));
            }
            (u64::from(v), 5)
        }
        255 => {
            if rdr.len() < 9 {
                return Err(ConsensusError::BadBlock("signet: compact size"));
            }
            let v = u64::from_le_bytes(rdr[1..9].try_into().expect("8 bytes"));
            if v <= u64::from(u32::MAX) {
                return Err(ConsensusError::BadBlock("signet: non-minimal compact size"));
            }
            (v, 9)
        }
    };
    *rdr = &rdr[n..];
    Ok(v)
}

#[doc(hidden)]
pub fn read_script(rdr: &mut &[u8]) -> Result<ScriptBuf, ConsensusError> {
    let n = read_signet_compact(rdr)? as usize;
    if rdr.len() < n {
        return Err(ConsensusError::BadBlock("signet: scriptSig short"));
    }
    let s = ScriptBuf::from_bytes(rdr[..n].to_vec());
    *rdr = &rdr[n..];
    Ok(s)
}

#[doc(hidden)]
pub fn read_witness_stack(rdr: &mut &[u8]) -> Result<Witness, ConsensusError> {
    let count = read_signet_compact(rdr)? as usize;
    if count > rdr.len() {
        return Err(ConsensusError::BadBlock("signet: witness count"));
    }
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let n = read_signet_compact(rdr)? as usize;
        if rdr.len() < n {
            return Err(ConsensusError::BadBlock("signet: witness short"));
        }
        items.push(rdr[..n].to_vec());
        *rdr = &rdr[n..];
    }
    let refs: Vec<&[u8]> = items.iter().map(|v| v.as_slice()).collect();
    Ok(Witness::from_slice(&refs))
}

#[doc(hidden)]
pub fn modified_merkle_root(
    modified_cb: &Transaction,
    block: &Block,
) -> Result<bitcoin::TxMerkleNode, ConsensusError> {
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(block.txdata.len());
    leaves.push(modified_cb.compute_txid().to_byte_array());
    for tx in block.txdata.iter().skip(1) {
        leaves.push(tx.compute_txid().to_byte_array());
    }
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            let last = *leaves.last().expect("signet merkle loop keeps a leaf");
            leaves.push(last);
        }
        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks(2) {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0]);
            buf[32..].copy_from_slice(&pair[1]);
            next.push(*sha256d::Hash::hash(&buf).as_byte_array());
        }
        leaves = next;
    }
    Ok(bitcoin::TxMerkleNode::from_byte_array(leaves[0]))
}

#[doc(hidden)]
pub fn verify_challenge_spend(
    to_spend: &Transaction,
    to_sign: &Transaction,
    challenge: &Script,
) -> Result<(), ConsensusError> {
    let prevout = TxOut {
        value: to_spend.output[0].value,
        script_pubkey: ScriptBuf::from_bytes(challenge.as_bytes().to_vec()),
    };
    let mut job = ScriptCheckJob::try_new(
        vec![prevout],
        to_sign.clone(),
        crate::block::ScriptVerifyFlags::buried(false, false, true, true, false),
    )?;
    job.null_dummy = true;
    job.witness_active = true;
    match crate::script::verify_job_all_inputs(&job) {
        Ok(()) => Ok(()),
        Err(_) => crate::trust::soften(ConsensusError::BadBlock("signet solution invalid")),
    }
}
