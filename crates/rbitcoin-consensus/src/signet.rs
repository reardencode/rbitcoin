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
const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];

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

    let (to_spend, to_sign) = signet_challenge_transactions(block, challenge)?;
    verify_challenge_spend(&to_spend, &to_sign, challenge)
}

/// BIP325 `to_spend` / `to_sign` pair. The challenge script is `to_sign`'s prevout.
// btc-lean: BLK-126 INV-086
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
    let mut ss = vec![0x00];
    push_data(&mut ss, &block_data);
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
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
        }],
    };

    Ok((to_spend, to_sign))
}

/// Core `CScript << std::span<const std::byte>`: direct push below 76 bytes, then
/// PUSHDATA1, PUSHDATA2, or PUSHDATA4. A one-byte payload is not turned into `OP_N`.
fn push_data(out: &mut Vec<u8>, data: &[u8]) {
    if data.len() < 0x4c {
        out.push(data.len() as u8);
    } else if let Ok(n) = u8::try_from(data.len()) {
        out.push(0x4c);
        out.push(n);
    } else if let Ok(n) = u16::try_from(data.len()) {
        out.push(0x4d);
        out.extend_from_slice(&n.to_le_bytes());
    } else {
        out.push(0x4e);
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
}

fn witness_commitment_index(coinbase: &Transaction) -> Option<usize> {
    crate::block::witness_commitment_vout_index(coinbase)
}

/// Core `GetScriptOp`: the opcode at `pc` and its push payload (empty for a non-push).
/// `None` at the end of the script or on a truncated push.
fn next_script_op<'a>(spk: &'a [u8], pc: &mut usize) -> Option<(u8, &'a [u8])> {
    let op = *spk.get(*pc)?;
    let mut at = *pc + 1;
    let len = match op {
        0x01..=0x4b => usize::from(op),
        0x4c => {
            let n = *spk.get(at)?;
            at += 1;
            usize::from(n)
        }
        0x4d => {
            let n = spk.get(at..at + 2)?;
            at += 2;
            usize::from(u16::from_le_bytes([n[0], n[1]]))
        }
        0x4e => {
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
/// [`push_data`], so the modified coinbase txid matches Core.
fn fetch_and_clear_signet_section(spk: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
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
                push_data(&mut replacement, &SIGNET_HEADER);
                continue;
            }
        }
        push_data(&mut replacement, data);
    }

    solution.map(|sol| (sol, replacement))
}

fn extract_header_payload(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() > SIGNET_HEADER.len() && data.starts_with(&SIGNET_HEADER) {
        Some(data[SIGNET_HEADER.len()..].to_vec())
    } else {
        None
    }
}

fn parse_signet_solution(solution: &[u8]) -> Result<(ScriptBuf, Witness), ConsensusError> {
    let mut rdr = solution;
    let script_sig = read_script(&mut rdr)?;
    let witness = read_witness_stack(&mut rdr)?;
    if !rdr.is_empty() {
        return Err(ConsensusError::BadBlock("signet: extraneous solution data"));
    }
    Ok((script_sig, witness))
}

fn read_signet_compact(rdr: &mut &[u8]) -> Result<u64, ConsensusError> {
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

fn read_script(rdr: &mut &[u8]) -> Result<ScriptBuf, ConsensusError> {
    let n = read_signet_compact(rdr)? as usize;
    if rdr.len() < n {
        return Err(ConsensusError::BadBlock("signet: scriptSig short"));
    }
    let s = ScriptBuf::from_bytes(rdr[..n].to_vec());
    *rdr = &rdr[n..];
    Ok(s)
}

fn read_witness_stack(rdr: &mut &[u8]) -> Result<Witness, ConsensusError> {
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

fn modified_merkle_root(
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
            let last = *leaves.last().unwrap();
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

fn verify_challenge_spend(
    to_spend: &Transaction,
    to_sign: &Transaction,
    challenge: &Script,
) -> Result<(), ConsensusError> {
    let prevout = TxOut {
        value: to_spend.output[0].value,
        script_pubkey: ScriptBuf::from_bytes(challenge.as_bytes().to_vec()),
    };
    let mut job = ScriptCheckJob::new(
        vec![prevout],
        to_sign.clone(),
        crate::block::ScriptVerifyFlags::buried(false, false, true, true, false),
    );
    job.null_dummy = true;
    job.witness_active = true;
    crate::script::verify_job_all_inputs(&job)
        .map_err(|_| ConsensusError::BadBlock("signet solution invalid"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::deserialize;

    #[test]
    fn default_challenge_parses() {
        let c = default_signet_challenge();
        assert!(c.as_bytes().len() > 70);
        assert_eq!(c.as_bytes()[0], 0x51); // OP_1
    }

    #[test]
    fn extract_signet_header_payload() {
        let mut push = SIGNET_HEADER.to_vec();
        push.extend_from_slice(&[0x01, 0x02, 0x03]);
        let sol = extract_header_payload(&push).unwrap();
        assert_eq!(sol, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn fetch_and_clear_rewrites_push() {
        // OP_RETURN + push(header||0xab)
        let mut spk = vec![0x6a, 0x05];
        spk.extend_from_slice(&SIGNET_HEADER);
        spk.push(0xab);
        let (sol, stripped) = fetch_and_clear_signet_section(&spk).unwrap();
        assert_eq!(sol, vec![0xab]);
        // stripped should still start with OP_RETURN
        assert_eq!(stripped[0], 0x6a);
    }

    #[test]
    fn custom_challenge_derives_expected_wire_magic() {
        let challenge = ScriptBuf::from_bytes(vec![0x51]);
        assert_eq!(
            signet_magic(challenge.as_script()),
            [0x54, 0xd2, 0x6f, 0xbd]
        );
        assert_eq!(
            signet_magic(default_signet_challenge().as_script()),
            [0x0a, 0x03, 0xcf, 0x40]
        );
    }

    #[test]
    fn signet_block_1_rejects_mutated_solution() {
        let raw = include_bytes!("../tests/fixtures/signet_block_1.bin");
        let mut block: Block = deserialize(raw).expect("decode");
        // Flip a byte in the witness-commitment output (destroys signature).
        let spk = block.txdata[0].output[1].script_pubkey.as_bytes().to_vec();
        let mut bad = spk.clone();
        *bad.last_mut().unwrap() ^= 0xff;
        block.txdata[0].output[1].script_pubkey = ScriptBuf::from_bytes(bad);
        let challenge = default_signet_challenge();
        assert!(validate_signet_block_solution(&block, challenge.as_script()).is_err());
    }

    #[test]
    fn to_spend_script_sig_starts_with_op_0() {
        let raw = include_bytes!("../tests/fixtures/signet_block_1.bin");
        let block: Block = deserialize(raw).unwrap();
        let challenge = default_signet_challenge();
        let (to_spend, _) = signet_challenge_transactions(&block, challenge.as_script()).unwrap();
        let ss = to_spend.input[0].script_sig.as_bytes();
        assert_eq!(ss[0], 0x00, "Core CScript(OP_0) then push(block_data)");
    }

    #[test]
    fn genesis_prev_skips_challenge() {
        let raw = include_bytes!("../tests/fixtures/signet_block_1.bin");
        let mut block: Block = deserialize(raw).unwrap();
        block.header.prev_blockhash = bitcoin::BlockHash::from_byte_array([0u8; 32]);
        // Empty txs would fail for non-genesis; genesis path returns Ok first.
        block.txdata.clear();
        validate_signet_block_solution(&block, Script::from_bytes(&[0x51])).unwrap();
    }

    #[test]
    fn empty_block_and_missing_commitment_errors() {
        let challenge = default_signet_challenge();
        let raw = include_bytes!("../tests/fixtures/signet_block_1.bin");
        let mut block: Block = deserialize(raw).unwrap();
        block.txdata.clear();
        assert!(matches!(
            signet_challenge_transactions(&block, challenge.as_script()),
            Err(ConsensusError::BadBlock(_))
        ));
        let mut block: Block = deserialize(raw).unwrap();
        // Strip commitment-looking outputs from coinbase.
        block.txdata[0].output.clear();
        block.txdata[0].output.push(TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        });
        assert!(matches!(
            signet_challenge_transactions(&block, challenge.as_script()),
            Err(ConsensusError::BadBlock(_))
        ));
    }

    #[test]
    fn missing_signet_section_lets_challenge_script_decide() {
        // Bare BIP141 commitment, no SIGNET_HEADER: Core spends with an empty
        // scriptSig and witness and lets VerifyScript decide for any challenge.
        let cb = coinbase_outputs(vec![bip141_commitment_spk(0x00)]);
        let block = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: bitcoin::BlockHash::from_byte_array([1u8; 32]),
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                time: 1,
                bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![cb],
        };
        for challenge in [vec![0x51], vec![0x52], vec![0x74, 0x00, 0x87]] {
            let challenge = ScriptBuf::from_bytes(challenge);
            let (to_spend, to_sign) =
                signet_challenge_transactions(&block, challenge.as_script()).unwrap();
            assert!(to_sign.input[0].script_sig.is_empty());
            assert!(to_sign.input[0].witness.is_empty());
            assert_eq!(to_spend.output[0].script_pubkey, challenge);
            validate_signet_block_solution(&block, challenge.as_script()).unwrap();
        }
        let err = validate_signet_block_solution(&block, default_signet_challenge().as_script())
            .unwrap_err();
        assert!(err.to_string().contains("signet solution invalid"), "{err}");
    }

    #[test]
    fn push_data_all_length_encodings() {
        let mut short = Vec::new();
        push_data(&mut short, &[0xab]);
        assert_eq!(short, vec![0x01, 0xab]);

        let mid = vec![0u8; 0x4c];
        let mut out = Vec::new();
        push_data(&mut out, &mid);
        assert_eq!(out[0], 0x4c);
        assert_eq!(out[1], 0x4c);
        assert_eq!(&out[2..], mid.as_slice());

        let long = vec![0x11u8; 300];
        let mut out2 = Vec::new();
        push_data(&mut out2, &long);
        assert_eq!(out2[0], 0x4d);
        assert_eq!(u16::from_le_bytes([out2[1], out2[2]]), 300);
        assert_eq!(&out2[3..], long.as_slice());
    }

    #[test]
    fn fetch_and_clear_pushdata1_and_pushdata2() {
        // OP_RETURN + PUSHDATA1(header||payload)
        let mut payload = SIGNET_HEADER.to_vec();
        payload.extend_from_slice(&[0xde, 0xad]);
        let mut spk = vec![0x6a, 0x4c, payload.len() as u8];
        spk.extend_from_slice(&payload);
        let (sol, stripped) = fetch_and_clear_signet_section(&spk).unwrap();
        assert_eq!(sol, vec![0xde, 0xad]);
        assert_eq!(stripped[0], 0x6a);

        // PUSHDATA2 path
        let mut payload2 = SIGNET_HEADER.to_vec();
        payload2.push(0xbe);
        let mut spk2 = vec![0x6a, 0x4d];
        spk2.extend_from_slice(&(payload2.len() as u16).to_le_bytes());
        spk2.extend_from_slice(&payload2);
        let (sol2, _) = fetch_and_clear_signet_section(&spk2).unwrap();
        assert_eq!(sol2, vec![0xbe]);
        // A byte after the push must survive. `pc *= n` skips it.
        spk2.push(0x51);
        let (sol2, repl2) = fetch_and_clear_signet_section(&spk2).unwrap();
        assert_eq!(sol2, vec![0xbe]);
        assert!(repl2.ends_with(&[0x51]), "{repl2:?}");

        // Truncated push → None
        assert!(fetch_and_clear_signet_section(&[0x05, 0x01]).is_none());
        assert!(fetch_and_clear_signet_section(&[0x4c, 0x05, 0x01]).is_none());
        assert!(fetch_and_clear_signet_section(&[0x4d, 0x05, 0x00, 0x01]).is_none());
        // OP_0 pass-through without solution
        assert!(fetch_and_clear_signet_section(&[0x00, 0x51]).is_none());
        // Non-header push retained
        let no_hdr = vec![0x03, 0xaa, 0xbb, 0xcc];
        assert!(fetch_and_clear_signet_section(&no_hdr).is_none());
        let _ = no_hdr;
    }

    #[test]
    #[allow(clippy::cognitive_complexity)] // one parser, many length boundaries
    fn compact_size_and_solution_parse_errors() {
        use rbitcoin_primitives::read_compact_size_from;
        assert_eq!(read_compact_size_from(&mut (&[0u8][..])).unwrap(), 0);
        assert_eq!(read_compact_size_from(&mut (&[252u8][..])).unwrap(), 252);
        // 253 + u16 LE
        let mut r = &[253u8, 0x01, 0x00][..];
        assert_eq!(read_compact_size_from(&mut r).unwrap(), 1);
        // 254 + u32
        let mut r = &[254u8, 0x02, 0x00, 0x00, 0x00][..];
        assert_eq!(read_compact_size_from(&mut r).unwrap(), 2);
        // 255 + u64
        let mut r = &[255u8, 0x03, 0, 0, 0, 0, 0, 0, 0][..];
        assert_eq!(read_compact_size_from(&mut r).unwrap(), 3);

        assert!(read_compact_size_from(&mut (&[][..])).is_err());
        assert!(read_compact_size_from(&mut (&[253u8][..])).is_err());
        assert!(read_compact_size_from(&mut (&[254u8, 0][..])).is_err());
        assert!(read_compact_size_from(&mut (&[255u8, 0, 0, 0][..])).is_err());

        // A push that is only the header has no payload (`len > header`, not `>=`).
        let mut header_only = vec![SIGNET_HEADER.len() as u8];
        header_only.extend_from_slice(&SIGNET_HEADER);
        assert!(fetch_and_clear_signet_section(&header_only).is_none());
        // Script bytes that end the buffer are not "short"; the witness count is.
        let err = parse_signet_solution(&[0x01, 0xaa]).unwrap_err();
        assert!(!err.to_string().contains("scriptSig short"), "{err}");
        // A witness item that fills the buffer is complete.
        let (ss, wit) = parse_signet_solution(&[0x00, 0x01, 0x01, 0xaa]).unwrap();
        assert!(ss.is_empty());
        assert_eq!(wit.to_vec(), vec![vec![0xaa]]);
        // Empty solution: scriptSig compact 0 + witness count 0.
        let (ss, wit) = parse_signet_solution(&[0x00, 0x00]).unwrap();
        assert!(ss.is_empty());
        assert_eq!(wit.len(), 0);
        // Truncated CompactSize in the solution.
        assert!(parse_signet_solution(&[253]).is_err());
        // Extraneous tail.
        assert!(parse_signet_solution(&[0x00, 0x00, 0xff]).is_err());
        // Short script.
        assert!(parse_signet_solution(&[0x02, 0xaa]).is_err());
        // Short witness item.
        assert!(parse_signet_solution(&[0x00, 0x01, 0x02, 0xaa]).is_err());
        // Non-minimal witness count 0 (253, 0x0000).
        let err = parse_signet_solution(&[0x00, 253, 0x00, 0x00]).unwrap_err();
        assert!(err.to_string().contains("non-minimal"), "{err}");
        // 253 is the smallest minimal 3-byte encoding. `v <= 253` rejects it.
        let mut at_253 = vec![253, 253, 0];
        at_253.extend(vec![0x11u8; 253]);
        at_253.push(0);
        let (ss, wit) = parse_signet_solution(&at_253).unwrap();
        assert_eq!(ss.len(), 253);
        assert_eq!(wit.len(), 0);
        // u16::MAX fits in 3 bytes, so a 5-byte form is non-minimal.
        let err = parse_signet_solution(&[254, 0xff, 0xff, 0x00, 0x00]).unwrap_err();
        assert!(err.to_string().contains("non-minimal"), "{err}");
        let err = parse_signet_solution(&[254, 0x00, 0x00, 0x00]).unwrap_err();
        assert!(err.to_string().contains("compact size"), "{err}");
        let err = parse_signet_solution(&[255, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]).unwrap_err();
        assert!(err.to_string().contains("non-minimal"), "{err}");
        let err = parse_signet_solution(&[255, 0, 0, 0, 0, 0, 0, 0]).unwrap_err();
        assert!(err.to_string().contains("compact size"), "{err}");
        // Huge count must fail before allocating the stack.
        let mut huge = vec![0x00, 255];
        huge.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse_signet_solution(&huge).is_err());
    }

    #[test]
    fn signet_section_pushdata4_and_minimal_reencode() {
        let mut script = vec![0x4e, 8, 0, 0, 0];
        script.extend_from_slice(&SIGNET_HEADER);
        script.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let (sol, repl) = fetch_and_clear_signet_section(&script).expect("pushdata4");
        assert_eq!(sol, vec![0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(&repl[..5], &[4, 0xec, 0xc7, 0xda, 0xa2]);
        // Four single-byte opcodes put pc at 5, so `pc * k` is not `pc + k`.
        let mut shifted = vec![0x51, 0x51, 0x51, 0x51, 0x4e, 5, 0, 0, 0];
        shifted.extend_from_slice(&SIGNET_HEADER);
        shifted.push(0x7e);
        // After the payload. `pc *= n` skips this opcode.
        shifted.push(0x52);
        let (sol, repl) = fetch_and_clear_signet_section(&shifted).expect("shifted pushdata4");
        assert_eq!(sol, vec![0x7e]);
        assert_eq!(repl.iter().filter(|b| **b == 0x51).count(), 4);
        assert!(repl.ends_with(&[0x52]), "{repl:?}");
        // Exactly three length bytes: `pc + 3 == len` must not read past the script.
        assert!(fetch_and_clear_signet_section(&[0x51, 0x51, 0x51, 0x51, 0x4e, 0, 0, 0]).is_none());
        // Non-minimal OP_PUSHDATA1 of one byte re-encodes as a direct push.
        let (sol, repl) = fetch_and_clear_signet_section(&[
            0x4c, 8, 0xec, 0xc7, 0xda, 0xa2, 1, 2, 3, 4, 0x4c, 1, 0xab,
        ])
        .expect("pushdata1");
        assert_eq!(sol, vec![1, 2, 3, 4]);
        assert!(repl.ends_with(&[1, 0xab]), "{repl:?}");
        // Truncation after a parsed section keeps the solution.
        let mut partial = vec![0x05];
        partial.extend_from_slice(&SIGNET_HEADER);
        partial.push(0x11);
        partial.push(0x4c);
        let (sol, _) = fetch_and_clear_signet_section(&partial).expect("truncated tail");
        assert_eq!(sol, vec![0x11]);
    }

    #[test]
    fn signet_section_reencodes_pushes_like_core_cscript() {
        // Core FetchAndClearCommitmentSection: an empty push (OP_0 or a zero-length
        // PUSHDATA1/2/4) is re-emitted as its bare opcode; a non-empty push goes
        // through CScript `<<` (direct, PUSHDATA1, PUSHDATA2, or PUSHDATA4).
        let mut spk = vec![0x6a, 0x4c, 0x00, 0x05];
        spk.extend_from_slice(&SIGNET_HEADER);
        spk.extend_from_slice(&[0x11, 0x4d, 0x00, 0x00, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let (sol, repl) = fetch_and_clear_signet_section(&spk).expect("section");
        assert_eq!(sol, vec![0x11]);
        let mut want = vec![0x6a, 0x4c, 0x04];
        want.extend_from_slice(&SIGNET_HEADER);
        want.extend_from_slice(&[0x4d, 0x4e, 0x00]);
        assert_eq!(repl, want);

        let big = vec![0x22u8; 0x1_0000];
        let mut spk = vec![0x05];
        spk.extend_from_slice(&SIGNET_HEADER);
        spk.push(0x11);
        spk.extend_from_slice(&[0x4e, 0x00, 0x00, 0x01, 0x00]);
        spk.extend_from_slice(&big);
        let (_, repl) = fetch_and_clear_signet_section(&spk).expect("section");
        let mut want = vec![0x04];
        want.extend_from_slice(&SIGNET_HEADER);
        want.extend_from_slice(&[0x4e, 0x00, 0x00, 0x01, 0x00]);
        want.extend_from_slice(&big);
        assert_eq!(repl, want);
    }

    #[test]
    fn modified_merkle_odd_leaf_count() {
        let raw = include_bytes!("../tests/fixtures/signet_block_1.bin");
        let block: Block = deserialize(raw).unwrap();
        // Two non-coinbase leaves force at least one pairing; invent a second dummy tx leaf
        // by cloning block with an extra empty-ish tx for merkle shape.
        let cb = block.txdata[0].clone();
        let root = modified_merkle_root(&cb, &block).unwrap();
        assert_ne!(root.to_byte_array(), [0u8; 32]);
        if block.txdata.len() > 1 {
            assert_ne!(root.to_byte_array(), cb.compute_txid().to_byte_array());
        }
        // Odd: only coinbase
        let solo = Block {
            header: block.header,
            txdata: vec![cb.clone()],
        };
        let r2 = modified_merkle_root(&cb, &solo).unwrap();
        assert_eq!(r2.to_byte_array(), cb.compute_txid().to_byte_array());
        let _ = cb;
    }

    #[test]
    // btc-lean: BLK-126 INV-086
    fn witness_commitment_index_finds_magic() {
        let raw = include_bytes!("../tests/fixtures/signet_block_1.bin");
        let block: Block = deserialize(raw).unwrap();
        assert!(witness_commitment_index(&block.txdata[0]).is_some());
    }

    fn bip141_commitment_spk(hash_byte: u8) -> Vec<u8> {
        let mut v = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        v.extend(std::iter::repeat_n(hash_byte, 32));
        v
    }

    fn coinbase_outputs(spks: Vec<Vec<u8>>) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x00, 0x00]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: spks
                .into_iter()
                .map(|script_pubkey| TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::from_bytes(script_pubkey),
                })
                .collect(),
        }
    }

    #[test]
    fn witness_commitment_index_last_exact_38_byte() {
        let first = bip141_commitment_spk(0x00);
        let last = bip141_commitment_spk(0x11);
        let tx = coinbase_outputs(vec![first, last]);
        assert_eq!(witness_commitment_index(&tx), Some(1));

        let substring = vec![0x6a, 0x04, 0xaa, 0x21, 0xa9, 0xed];
        let tx = coinbase_outputs(vec![substring, bip141_commitment_spk(0x22)]);
        assert_eq!(witness_commitment_index(&tx), Some(1));

        let only_sub = coinbase_outputs(vec![vec![0x6a, 0x04, 0xaa, 0x21, 0xa9, 0xed]]);
        assert!(witness_commitment_index(&only_sub).is_none());
    }

    fn challenge_pair(spk: ScriptBuf) -> (Transaction, Transaction) {
        let to_spend = Transaction {
            version: bitcoin::transaction::Version::non_standard(0),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: spk,
            }],
        };
        let txid = to_spend.compute_txid();
        let to_sign = Transaction {
            version: bitcoin::transaction::Version::non_standard(0),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
            }],
        };
        (to_spend, to_sign)
    }

    #[test]
    fn signet_challenge_op_true_twice_is_not_cleanstack() {
        let challenge = ScriptBuf::from_bytes(vec![0x51, 0x51]);
        let (to_spend, to_sign) = challenge_pair(challenge.clone());
        verify_challenge_spend(&to_spend, &to_sign, challenge.as_script()).unwrap();
    }

    #[test]
    fn signet_challenge_p2wpkh_empty_witness_rejected() {
        let mut spk = vec![0x00, 0x14];
        spk.extend([0u8; 20]);
        let challenge = ScriptBuf::from_bytes(spk);
        let (to_spend, to_sign) = challenge_pair(challenge.clone());
        assert!(verify_challenge_spend(&to_spend, &to_sign, challenge.as_script()).is_err());
    }

    #[test]
    fn push_data_mid_and_unknown_op_passthrough() {
        // push_data uses PUSHDATA2 for 0xff < len <= 0xffff.
        let mid = vec![0u8; 300];
        let mut out = Vec::new();
        push_data(&mut out, &mid);
        assert_eq!(out[0], 0x4d);
        assert_eq!(u16::from_le_bytes([out[1], out[2]]), 300);
        // Truncated PUSHDATA4 stops the scan (no solution).
        assert!(fetch_and_clear_signet_section(&[0x4e, 0x05, 0x00, 0x00, 0x00, 0x01]).is_none());
        // OP_RETURN + OP_TRUE: no signet header → None.
        assert!(fetch_and_clear_signet_section(&[0x6a, 0x51]).is_none());
    }

    #[test]
    fn modified_merkle_three_leaves() {
        let raw = include_bytes!("../tests/fixtures/signet_block_1.bin");
        let block: Block = deserialize(raw).unwrap();
        let cb = block.txdata[0].clone();
        // Build block with coinbase + 2 dummy non-cb (odd non-cb count after strip).
        let dummy = |n: u8| Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([n; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let multi = Block {
            header: block.header,
            txdata: vec![cb.clone(), dummy(1), dummy(2)],
        };
        let root = modified_merkle_root(&cb, &multi).unwrap();
        assert_ne!(root.to_byte_array(), cb.compute_txid().to_byte_array());
        let _ = cb;
    }
}
