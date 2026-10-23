//! Script differential against `bitcoinconsensus`.
//!
//! Every executed input is `0xFE`, then a Core flag word, a shape, and a
//! payload. Anything else is a skip. Shape 0 is opcode soup: transaction
//! version, sequence, locktime, amount, then length-prefixed scriptSig,
//! scriptPubKey, and witness. Shapes 1–8 are fixed discriminators. Flag
//! combinations that abort `libbitcoinconsensus` are [`KernelCmp::Skip`].
//! A different verdict is [`KernelCmp::Disagree`] even when our word is
//! stricter than Core's.

use std::time::Duration;

use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::{hash160, sha256, Hash};
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, CompactTarget, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Witness,
};
use bitcoinconsensus::{
    verify_with_flags, Error, Utxo, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY,
    VERIFY_DERSIG, VERIFY_NULLDUMMY, VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS,
};
use rbitcoin_consensus::{
    signet_challenge_transactions, validate_signet_block_solution, verify_tx_scripts_with_flags,
    witness_commitment_script, ChainParams, ScriptVerifyFlags, BIP16_EXCEPTION_MAINNET,
    TAPROOT_EXCEPTION_MAINNET,
};

use crate::script_kernel::KernelCmp;

pub const STRUCTURED: u8 = 0xFE;

const STRICTENC: u32 = 1 << 1;
const LOW_S: u32 = 1 << 3;
const MINIMALDATA: u32 = 1 << 6;
/// Core checks these. This interpreter has no field for them, so they stay
/// on the Core word only. A verdict change is a disagreement, not a skip.
/// Bits 18–20 are not `discourage_upgradable_witness` (bit 12).
const UNMAPPED_POLICY: u32 = (1 << 5) | (1 << 7) | (1 << 18) | (1 << 19) | (1 << 20);
const CLEANSTACK: u32 = 1 << 8;
const DISCOURAGE_UPGRADABLE_WITNESS: u32 = 1 << 12;
const MINIMALIF: u32 = 1 << 13;
const NULLFAIL: u32 = 1 << 14;
const WITNESS_PUBKEYTYPE: u32 = 1 << 15;
const CONST_SCRIPTCODE: u32 = 1 << 16;

const SHAPE_RAW: u8 = 0;
const SHAPE_CMS: u8 = 1;
const SHAPE_DER: u8 = 2;
const SHAPE_P2PKH: u8 = 3;
const SHAPE_P2WPKH: u8 = 4;
const SHAPE_V0: u8 = 5;
const SHAPE_DERSIG: u8 = 6;
const SHAPE_BIP16: u8 = 7;
const SHAPE_SIGNET: u8 = 8;

/// Thread CPU time for our verifier. libFuzzer `-timeout=1` is the hang
/// backstop; this bound is what fails a quadratic script. Do not start looser.
/// A single sample over the bound is run once more. Panic only when both
/// samples exceed it, so a scheduler stall is not a finding.
pub const SCRIPT_KERNEL_VERIFY_BUDGET: Duration = Duration::from_millis(100);

pub fn verify_budget_exceeded(elapsed: Duration) -> bool {
    elapsed > SCRIPT_KERNEL_VERIFY_BUDGET
}

/// Both samples have to be over the budget. A missing clock does not panic.
pub fn verify_budget_confirmed(first: Option<Duration>, second: Option<Duration>) -> bool {
    match (first, second) {
        (Some(a), Some(b)) => verify_budget_exceeded(a) && verify_budget_exceeded(b),
        _ => false,
    }
}

#[repr(C)]
struct TimeSpec {
    tv_sec: i64,
    tv_nsec: i64,
}

fn thread_cpu_now() -> Option<Duration> {
    const CLOCK_THREAD_CPUTIME_ID: i32 = 3;
    extern "C" {
        fn clock_gettime(clk_id: i32, tp: *mut TimeSpec) -> i32;
    }
    let mut ts = TimeSpec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a timespec this function owns. `clock_gettime` writes
    // that object and does not retain the pointer. Clock 3 is
    // CLOCK_THREAD_CPUTIME_ID on Linux.
    if unsafe { clock_gettime(CLOCK_THREAD_CPUTIME_ID, &mut ts) } != 0 {
        return None;
    }
    Some(
        Duration::from_secs(ts.tv_sec.max(0) as u64)
            + Duration::from_nanos(ts.tv_nsec.max(0) as u64),
    )
}

fn sample_cpu<T>(verify: &mut dyn FnMut() -> T) -> (T, Option<Duration>) {
    let start = thread_cpu_now();
    let value = verify();
    let elapsed = match (start, thread_cpu_now()) {
        (Some(a), Some(b)) => Some(b.saturating_sub(a)),
        _ => None,
    };
    (value, elapsed)
}

fn our_verify_within_budget<T>(prefix: &[u8], mut verify: impl FnMut() -> T) -> T {
    let (value, first) = sample_cpu(&mut verify);
    if !first.is_some_and(verify_budget_exceeded) {
        return value;
    }
    let (value, second) = sample_cpu(&mut verify);
    if verify_budget_confirmed(first, second) {
        let n = prefix.len().min(8);
        panic!(
            "script-kernel verify budget first={first:?} second={second:?} prefix={:02x?}",
            &prefix[..n]
        );
    }
    value
}

/// Core `GetBlockScriptFlags` (validation.cpp): P2SH|WITNESS|TAPROOT from
/// genesis, replaced only by the two exception hashes, then the height-gated
/// ORs. Not [`bitcoinconsensus::height_to_flags`].
pub fn core_block_script_flags(params: &ChainParams, height: u32, block_hash: &[u8; 32]) -> u32 {
    let mut flags = if *block_hash == BIP16_EXCEPTION_MAINNET {
        0
    } else if *block_hash == TAPROOT_EXCEPTION_MAINNET {
        VERIFY_P2SH | VERIFY_WITNESS
    } else {
        VERIFY_P2SH | VERIFY_WITNESS | VERIFY_TAPROOT
    };
    if params.bip66_active_at(height) {
        flags |= VERIFY_DERSIG;
    }
    if params.bip65_active_at(height) {
        flags |= VERIFY_CHECKLOCKTIMEVERIFY;
    }
    if params.csv_active_at(height) {
        flags |= VERIFY_CHECKSEQUENCEVERIFY;
    }
    if params.segwit_active_at(height) {
        flags |= VERIFY_NULLDUMMY;
    }
    flags
}

/// WITNESS without P2SH, or CLEANSTACK without P2SH and WITNESS, aborts the C library.
pub fn flags_abort_libconsensus(flags: u32) -> bool {
    let p2sh = flags & VERIFY_P2SH != 0;
    let witness = flags & VERIFY_WITNESS != 0;
    let clean = flags & CLEANSTACK != 0;
    (witness && !p2sh) || (clean && (!p2sh || !witness))
}

pub fn flags_to_ours(flags: u32) -> ScriptVerifyFlags {
    let low_s = flags & LOW_S != 0;
    let strictenc = flags & STRICTENC != 0;
    ScriptVerifyFlags {
        bip65_active: flags & VERIFY_CHECKLOCKTIMEVERIFY != 0,
        bip112_active: flags & VERIFY_CHECKSEQUENCEVERIFY != 0,
        bip66_active: flags & VERIFY_DERSIG != 0 || low_s || strictenc,
        bip16_active: flags & VERIFY_P2SH != 0,
        taproot_active: flags & VERIFY_TAPROOT != 0,
        minimal_if: flags & MINIMALIF != 0,
        nullfail: flags & NULLFAIL != 0,
        low_s,
        strictenc,
        null_dummy: flags & VERIFY_NULLDUMMY != 0,
        minimal_data: flags & MINIMALDATA != 0,
        witness_pubkeytype: flags & WITNESS_PUBKEYTYPE != 0,
        witness_active: flags & VERIFY_WITNESS != 0,
        discourage_upgradable_witness: flags & DISCOURAGE_UPGRADABLE_WITNESS != 0,
        const_scriptcode: flags & CONST_SCRIPTCODE != 0,
        cleanstack: flags & CLEANSTACK != 0,
        heretical: rbitcoin_consensus::heretical::HereticalFlags::default(),
    }
}

pub fn core_accept(prevouts: &[TxOut], tx: &Transaction, flags: u32) -> bool {
    core_script_verdict(prevouts, tx, flags).unwrap_or(false)
}

/// `Ok` is a script verdict. `Err(ERR_INVALID_FLAGS)` means the C library
/// refused the flag word, which is not a script failure.
fn core_script_verdict(prevouts: &[TxOut], tx: &Transaction, flags: u32) -> Result<bool, Error> {
    let raw = serialize(tx);
    let spk = prevouts[0].script_pubkey.as_bytes();
    let amount = prevouts[0].value.to_sat();
    let utxos: Vec<Utxo> = prevouts
        .iter()
        .map(|o| Utxo {
            script_pubkey: o.script_pubkey.as_bytes().as_ptr(),
            script_pubkey_len: o.script_pubkey.len() as u32,
            value: o.value.to_sat() as i64,
        })
        .collect();
    let spent = if flags & VERIFY_TAPROOT != 0 {
        Some(utxos.as_slice())
    } else {
        None
    };
    match verify_with_flags(spk, amount, &raw, spent, 0, flags) {
        Ok(()) => Ok(true),
        Err(Error::ERR_INVALID_FLAGS) => Err(Error::ERR_INVALID_FLAGS),
        Err(_) => Ok(false),
    }
}

fn classify(ours: bool, core: bool) -> KernelCmp {
    if ours == core {
        KernelCmp::Agree { accept: ours }
    } else {
        KernelCmp::Disagree { ours, core }
    }
}

/// Run the shipped verifier and `bitcoinconsensus` on one spend.
pub fn compare_spend(prevouts: Vec<TxOut>, tx: Transaction, flags: u32) -> KernelCmp {
    compare_spend_prefixed(prevouts, tx, flags, &[])
}

fn compare_spend_prefixed(
    prevouts: Vec<TxOut>,
    tx: Transaction,
    flags: u32,
    prefix: &[u8],
) -> KernelCmp {
    if flags_abort_libconsensus(flags) {
        return KernelCmp::Skip;
    }
    debug_assert_eq!(UNMAPPED_POLICY & (VERIFY_P2SH | VERIFY_WITNESS), 0);
    let ours = our_verify_within_budget(prefix, || {
        verify_tx_scripts_with_flags(prevouts.clone(), tx.clone(), flags_to_ours(flags)).is_ok()
    });
    match core_script_verdict(&prevouts, &tx, flags) {
        Ok(core) => classify(ours, core),
        Err(Error::ERR_INVALID_FLAGS) => KernelCmp::Skip,
        Err(_) => classify(ours, false),
    }
}

fn spend(
    script_sig: Vec<u8>,
    script_pubkey: Vec<u8>,
    witness: Witness,
) -> (Vec<TxOut>, Transaction) {
    spend_fields(
        TxVersion::TWO,
        Sequence::MAX,
        LockTime::ZERO,
        Amount::from_sat(50_0000_0000),
        script_sig,
        script_pubkey,
        witness,
    )
}

fn spend_fields(
    version: TxVersion,
    sequence: Sequence,
    lock_time: LockTime,
    amount: Amount,
    script_sig: Vec<u8>,
    script_pubkey: Vec<u8>,
    witness: Witness,
) -> (Vec<TxOut>, Transaction) {
    let prevouts = vec![TxOut {
        value: amount,
        script_pubkey: ScriptBuf::from_bytes(script_pubkey),
    }];
    let tx = Transaction {
        version,
        lock_time,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([1; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::from_bytes(script_sig),
            sequence,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    (prevouts, tx)
}

/// Legacy CMS: empty signatures FindAndDelete `OP_0`. `OP_NOT` flips a soft
/// false into accept unless CONST_SCRIPTCODE hard-fails the deletion.
pub fn cms_empty_sig_spend() -> (Vec<TxOut>, Transaction) {
    let pk = compressed_pk();
    let mut spk = vec![0x00, 0x75, 0x52, 0x21];
    spk.extend_from_slice(&pk);
    spk.push(0x21);
    spk.extend_from_slice(&pk);
    spk.extend_from_slice(&[0x52, 0xae, 0x91]);
    spend(vec![0x00, 0x00, 0x00], spk, Witness::new())
}

/// Non-canonical DER (R = 00 01). DERSIG hard-fails; DERSIG off is a soft false
/// inverted by `OP_NOT`. Witness script, so typed P2WPKH is not this path.
pub fn witness_der_spend() -> (Vec<TxOut>, Transaction) {
    let redeem = vec![0xac, 0x91];
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(sha256::Hash::hash(&redeem).as_byte_array());
    let sig = vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01, 0x01];
    let pk = compressed_pk();
    let witness = Witness::from_slice(&[sig.as_slice(), pk.as_slice(), redeem.as_slice()]);
    spend(Vec::new(), spk, witness)
}

/// Bare CHECKSIG of the same non-canonical DER, inverted by `OP_NOT`.
pub fn nullfail_spend() -> (Vec<TxOut>, Transaction) {
    let sig = vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01, 0x01];
    let pk = compressed_pk();
    let mut ss = Vec::with_capacity(2 + sig.len() + pk.len());
    ss.push(sig.len() as u8);
    ss.extend_from_slice(&sig);
    ss.push(pk.len() as u8);
    ss.extend_from_slice(&pk);
    spend(ss, vec![0xac, 0x91], Witness::new())
}

/// Two pushes whose pubkey does not match the P2PKH program.
pub fn typed_p2pkh_spend() -> (Vec<TxOut>, Transaction) {
    let pk = compressed_pk();
    let mut spk = vec![0x76, 0xa9, 0x14];
    spk.extend_from_slice(&[0x11; 20]);
    spk.extend_from_slice(&[0x88, 0xac]);
    let mut ss = vec![0x01, 0xff, pk.len() as u8];
    ss.extend_from_slice(&pk);
    spend(ss, spk, Witness::new())
}

/// Witness length is not 2, so the typed P2WPKH entry rejects before ECDSA.
pub fn typed_p2wpkh_spend() -> (Vec<TxOut>, Transaction) {
    let mut spk = vec![0x00, 0x14];
    spk.extend_from_slice(&[0x22; 20]);
    let witness = Witness::from_slice(&[&[0xffu8][..]]);
    spend(Vec::new(), spk, witness)
}

/// v0 program whose bare execution is true and whose witness execution is not.
pub fn v0_program_spend() -> (Vec<TxOut>, Transaction) {
    let mut spk = vec![0x00, 0x14, 0x01];
    spk.extend_from_slice(&[0u8; 19]);
    spend(Vec::new(), spk, Witness::new())
}

fn compressed_pk() -> Vec<u8> {
    let mut pk = vec![0x02];
    pk.extend_from_slice(&[0x01; 32]);
    pk
}

fn read_u16(data: &[u8], at: &mut usize) -> Option<usize> {
    let b = data.get(*at..*at + 2)?;
    *at += 2;
    Some(u16::from_le_bytes([b[0], b[1]]) as usize)
}

fn raw_spend(payload: &[u8]) -> Option<(Vec<TxOut>, Transaction)> {
    let header = payload.get(..20)?;
    let version = i32::from_le_bytes(header[0..4].try_into().ok()?);
    let sequence = u32::from_le_bytes(header[4..8].try_into().ok()?);
    let lock_time = u32::from_le_bytes(header[8..12].try_into().ok()?);
    let amount = i64::from_le_bytes(header[12..20].try_into().ok()?);
    if amount < 0 {
        return None;
    }
    let mut at = 20usize;
    let sig_len = read_u16(payload, &mut at)?;
    if sig_len > 10_000 {
        return None;
    }
    let sig = payload.get(at..at + sig_len)?.to_vec();
    at += sig_len;
    let spk_len = read_u16(payload, &mut at)?;
    if spk_len > 10_000 {
        return None;
    }
    let spk = payload.get(at..at + spk_len)?.to_vec();
    at += spk_len;
    let n_wit = read_u16(payload, &mut at)?;
    if n_wit > 32 {
        return None;
    }
    let mut items = Vec::with_capacity(n_wit);
    for _ in 0..n_wit {
        let n = read_u16(payload, &mut at)?;
        if n > 10_000 {
            return None;
        }
        items.push(payload.get(at..at + n)?.to_vec());
        at += n;
    }
    let refs: Vec<&[u8]> = items.iter().map(|v| v.as_slice()).collect();
    Some(spend_fields(
        TxVersion::non_standard(version),
        Sequence::from_consensus(sequence),
        LockTime::from_consensus(lock_time),
        Amount::from_sat(amount as u64),
        sig,
        spk,
        Witness::from_slice(&refs),
    ))
}

/// Node flags and Core flags for one height, on `spend`.
pub fn compare_at_height(
    height: u32,
    block_hash: &[u8; 32],
    spend_tx: (Vec<TxOut>, Transaction),
    prefix: &[u8],
) -> KernelCmp {
    let params = ChainParams::mainnet();
    let core_flags = core_block_script_flags(&params, height, block_hash);
    if flags_abort_libconsensus(core_flags) {
        return KernelCmp::Skip;
    }
    let ours_flags = ScriptVerifyFlags::for_block(&params, height, block_hash, 0);
    let (prevouts, tx) = spend_tx;
    let ours = our_verify_within_budget(prefix, || {
        verify_tx_scripts_with_flags(prevouts.clone(), tx.clone(), ours_flags).is_ok()
    });
    let core = core_accept(&prevouts, &tx, core_flags);
    classify(ours, core)
}

pub fn compare_signet_empty(challenge: &[u8]) -> KernelCmp {
    compare_signet_empty_prefixed(challenge, &[])
}

fn compare_signet_empty_prefixed(challenge: &[u8], prefix: &[u8]) -> KernelCmp {
    if challenge.is_empty() || challenge.len() > 10_000 {
        return KernelCmp::Skip;
    }
    let block = signet_block_bare_commitment();
    let script = Script::from_bytes(challenge);
    let Ok((to_spend, to_sign)) = signet_challenge_transactions(&block, script) else {
        return KernelCmp::Skip;
    };
    let core_flags = VERIFY_P2SH | VERIFY_WITNESS | VERIFY_DERSIG | VERIFY_NULLDUMMY;
    let ours = our_verify_within_budget(prefix, || {
        validate_signet_block_solution(&block, script).is_ok()
    });
    let core = core_accept(&to_spend.output, &to_sign, core_flags);
    classify(ours, core)
}

fn signet_block_bare_commitment() -> Block {
    let spk = witness_commitment_script(std::iter::empty(), &[0u8; 32]);
    let cb = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x00, 0x00]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(spk),
        }],
    };
    Block {
        header: Header {
            version: Version::ONE,
            prev_blockhash: bitcoin::BlockHash::from_byte_array([1; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![cb],
    }
}

/// `0xFE || u32-le flags || shape || payload`. Any other prefix skips.
pub fn compare_kernel_bytes(data: &[u8]) -> Option<KernelCmp> {
    if data.first().copied() != Some(STRUCTURED) {
        return None;
    }
    compare_structured(&data[1..], data)
}

fn compare_structured(data: &[u8], input: &[u8]) -> Option<KernelCmp> {
    if data.len() < 5 {
        return None;
    }
    let flags = u32::from_le_bytes(data[0..4].try_into().ok()?);
    let shape = data[4];
    let payload = &data[5..];
    Some(match shape {
        SHAPE_RAW => {
            let (prev, tx) = raw_spend(payload)?;
            compare_spend_prefixed(prev, tx, flags, input)
        }
        SHAPE_CMS => {
            let pair = cms_empty_sig_spend();
            compare_spend_pair_prefixed(pair, flags, input)
        }
        SHAPE_DER => {
            let pair = witness_der_spend();
            compare_spend_pair_prefixed(pair, flags, input)
        }
        SHAPE_P2PKH => {
            let pair = typed_p2pkh_spend();
            compare_spend_pair_prefixed(pair, flags, input)
        }
        SHAPE_P2WPKH => {
            let pair = typed_p2wpkh_spend();
            compare_spend_pair_prefixed(pair, flags, input)
        }
        SHAPE_V0 => compare_v0_at_payload_height(payload, input),
        SHAPE_DERSIG => {
            let height = payload_height(payload);
            compare_at_height(height, &[0x11; 32], nullfail_spend(), input)
        }
        SHAPE_BIP16 => {
            compare_at_height(170_060, &BIP16_EXCEPTION_MAINNET, bip16_bare_spend(), input)
        }
        SHAPE_SIGNET => {
            let challenge = if payload.is_empty() {
                vec![0x52]
            } else {
                payload.to_vec()
            };
            compare_signet_empty_prefixed(&challenge, input)
        }
        _ => return None,
    })
}

fn compare_spend_pair_prefixed(
    pair: (Vec<TxOut>, Transaction),
    flags: u32,
    prefix: &[u8],
) -> KernelCmp {
    let (prev, tx) = pair;
    compare_spend_prefixed(prev, tx, flags, prefix)
}

/// v0 program vs `for_block` only once segwit is active.
///
/// Below that height `for_block` leaves WITNESS off, so this program is a
/// true bare script, while `GetBlockScriptFlags` has had WITNESS on since
/// genesis. A missing height is not treated as 1000.
fn compare_v0_at_payload_height(payload: &[u8], prefix: &[u8]) -> KernelCmp {
    if payload.len() < 4 {
        return KernelCmp::Skip;
    }
    let height = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if !ChainParams::mainnet().segwit_active_at(height) {
        return KernelCmp::Skip;
    }
    compare_at_height(height, &[0x11; 32], v0_program_spend(), prefix)
}

fn payload_height(payload: &[u8]) -> u32 {
    if payload.len() >= 4 {
        u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]])
    } else {
        1000
    }
}

/// P2SH shape whose redeem is `OP_RETURN`. Bare HASH160/EQUAL accepts.
fn bip16_bare_spend() -> (Vec<TxOut>, Transaction) {
    let redeem = [0x6au8];
    let h = hash160::Hash::hash(&redeem);
    let mut spk = vec![0xa9, 0x14];
    spk.extend_from_slice(h.as_byte_array());
    spk.push(0x87);
    spend(vec![0x01, 0x6a], spk, Witness::new())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use rbitcoin_consensus::verify_tx_scripts_with_flags;

    fn assert_classifies(prevouts: Vec<TxOut>, tx: Transaction, flags: u32, known_core: bool) {
        assert!(!flags_abort_libconsensus(flags), "fixture flags abort");
        let core = core_accept(&prevouts, &tx, flags);
        assert_eq!(core, known_core, "bitcoinconsensus bool");
        let ours = verify_tx_scripts_with_flags(prevouts.clone(), tx.clone(), flags_to_ours(flags))
            .is_ok();
        match compare_spend(prevouts, tx, flags) {
            KernelCmp::Agree { accept } if accept == ours && ours == core => {}
            KernelCmp::Disagree { ours: o, core: c } if o == ours && c == core && ours != core => {}
            other => panic!("classify ours={ours} core={core}: {other:?}"),
        }
    }

    #[test]
    fn cms_empty_sig_matches_core_bool() {
        let (prev, tx) = cms_empty_sig_spend();
        // Legal consensus word: empty sig is a soft fail, OP_NOT accepts.
        let legal = VERIFY_P2SH | VERIFY_WITNESS | VERIFY_NULLDUMMY;
        assert_classifies(prev.clone(), tx.clone(), legal, true);
        // CONST_SCRIPTCODE is outside libbitcoinconsensus VERIFY_ALL.
        let flags = legal | CONST_SCRIPTCODE;
        assert!(matches!(
            compare_spend(prev.clone(), tx.clone(), flags),
            KernelCmp::Skip
        ));
        let err = verify_tx_scripts_with_flags(prev, tx, flags_to_ours(flags)).unwrap_err();
        assert!(
            err.to_string().contains("SIG_FINDANDDELETE"),
            "CONST_SCRIPTCODE rejects the empty-sig OP_0 deletion: {err}"
        );
    }

    #[test]
    fn witness_der_false_vs_fail_matches_core_bool() {
        let flags = VERIFY_P2SH | VERIFY_WITNESS;
        let (prev, tx) = witness_der_spend();
        // DERSIG off, NULLFAIL off: soft false, OP_NOT accepts.
        assert_classifies(prev, tx, flags, true);
    }

    #[test]
    fn nullfail_policy_matches_core_bool() {
        let (prev, tx) = nullfail_spend();
        // DERSIG and NULLFAIL off: soft false, OP_NOT accepts.
        let legal = VERIFY_P2SH | VERIFY_WITNESS;
        assert_classifies(prev.clone(), tx.clone(), legal, true);
        // NULLFAIL is outside libbitcoinconsensus VERIFY_ALL.
        let flags = legal | NULLFAIL;
        assert!(matches!(
            compare_spend(prev.clone(), tx.clone(), flags),
            KernelCmp::Skip
        ));
        assert!(
            verify_tx_scripts_with_flags(prev, tx, flags_to_ours(flags)).is_err(),
            "our NULLFAIL rejects the non-canonical DER"
        );
    }

    #[test]
    fn typed_p2pkh_and_p2wpkh_entries_are_invoked() {
        let flags = VERIFY_P2SH | VERIFY_WITNESS;
        let (prev, tx) = typed_p2pkh_spend();
        let err = verify_tx_scripts_with_flags(prev.clone(), tx.clone(), flags_to_ours(flags))
            .unwrap_err();
        assert!(err.to_string().contains("p2pkh"), "{err}");
        assert_classifies(prev, tx, flags, false);

        let (prev, tx) = typed_p2wpkh_spend();
        let err = verify_tx_scripts_with_flags(prev.clone(), tx.clone(), flags_to_ours(flags))
            .unwrap_err();
        assert!(err.to_string().contains("p2wpkh"), "{err}");
        assert_classifies(prev, tx, flags, false);
    }

    #[test]
    fn v0_program_and_signet_empty_match_core_bool() {
        let short = vec![STRUCTURED, 0, 0, 0, 0, SHAPE_V0];
        assert!(
            matches!(compare_kernel_bytes(&short), Some(KernelCmp::Skip)),
            "a v0 input with no height is not height 1000"
        );
        let mut below = short.clone();
        below.extend_from_slice(&1000u32.to_le_bytes());
        assert!(
            matches!(compare_kernel_bytes(&below), Some(KernelCmp::Skip)),
            "pre-segwit v0 is not compared"
        );

        let (prev, tx) = v0_program_spend();
        let params = ChainParams::mainnet();
        let hash = [0x11u8; 32];
        let height = 481_824;
        let core_flags = core_block_script_flags(&params, height, &hash);
        let core = core_accept(&prev, &tx, core_flags);
        let ours_flags = ScriptVerifyFlags::for_block(&params, height, &hash, 0);
        let ours = verify_tx_scripts_with_flags(prev.clone(), tx.clone(), ours_flags).is_ok();
        assert_eq!(ours, core, "for_block and GetBlockScriptFlags diverge");
        assert!(!core, "empty v0 witness rejects once WITNESS is on");
        assert!(matches!(
            compare_at_height(height, &hash, (prev, tx), &[]),
            KernelCmp::Agree { accept: false }
        ));

        let challenge = [0x52u8];
        assert_ne!(challenge, [0x51]);
        let block = signet_block_bare_commitment();
        let (to_spend, to_sign) =
            signet_challenge_transactions(&block, Script::from_bytes(&challenge)).unwrap();
        let signet_flags = VERIFY_P2SH | VERIFY_WITNESS | VERIFY_DERSIG | VERIFY_NULLDUMMY;
        let core = core_accept(&to_spend.output, &to_sign, signet_flags);
        assert!(
            core,
            "OP_2 on an empty stack is true under Core signet flags"
        );
        let ours = validate_signet_block_solution(&block, Script::from_bytes(&challenge)).is_ok();
        match compare_signet_empty(&challenge) {
            KernelCmp::Agree { accept } if accept == ours && ours == core => {}
            KernelCmp::Disagree { ours: o, core: c } if o == ours && c == core && ours != core => {}
            other => panic!("signet ours={ours} core={core}: {other:?}"),
        }
    }

    #[test]
    fn op_success_bit_is_not_witness_program_policy() {
        // Witness v2, non-zero program. Anyone-can-spend unless bit 12 is set.
        // This libbitcoinconsensus refuses bit 19, so the compare skips.
        // The bit must not be applied as DISCOURAGE_UPGRADABLE_WITNESS.
        let (prev, tx) = spend(Vec::new(), vec![0x52, 0x02, 0x01, 0x01], Witness::new());
        let flags = VERIFY_P2SH | VERIFY_WITNESS | VERIFY_TAPROOT | (1 << 19);
        assert!(!flags_to_ours(flags).discourage_upgradable_witness);
        assert!(
            verify_tx_scripts_with_flags(prev.clone(), tx.clone(), flags_to_ours(flags)).is_ok()
        );
        assert!(matches!(compare_spend(prev, tx, flags), KernelCmp::Skip));

        let (prev, tx) = spend(Vec::new(), vec![0x52, 0x02, 0x01, 0x01], Witness::new());
        let flags = VERIFY_P2SH | VERIFY_WITNESS | VERIFY_TAPROOT | DISCOURAGE_UPGRADABLE_WITNESS;
        assert!(flags_to_ours(flags).discourage_upgradable_witness);
        assert!(
            verify_tx_scripts_with_flags(prev.clone(), tx.clone(), flags_to_ours(flags)).is_err()
        );
        assert!(matches!(compare_spend(prev, tx, flags), KernelCmp::Skip));
        for bit in [18u32, 20] {
            let word = VERIFY_P2SH | VERIFY_WITNESS | VERIFY_TAPROOT | (1 << bit);
            assert!(!flags_to_ours(word).discourage_upgradable_witness);
        }
    }

    #[test]
    fn witness_without_p2sh_is_a_skip() {
        let (prev, tx) = spend(vec![], vec![0x51], Witness::new());
        assert!(matches!(
            compare_spend(prev, tx, VERIFY_WITNESS),
            KernelCmp::Skip
        ));
        assert!(matches!(
            compare_spend(cms_empty_sig_spend().0, cms_empty_sig_spend().1, CLEANSTACK),
            KernelCmp::Skip
        ));
    }

    #[test]
    fn bip16_exception_script_is_compared() {
        let (prev, tx) = bip16_bare_spend();
        let params = ChainParams::mainnet();
        let core_flags = core_block_script_flags(&params, 170_060, &BIP16_EXCEPTION_MAINNET);
        assert_eq!(core_flags, 0, "exception block is flags none");
        let core = core_accept(&prev, &tx, core_flags);
        assert!(core, "bare HASH160/EQUAL accepts when P2SH is off");
        let ours_flags =
            ScriptVerifyFlags::for_block(&params, 170_060, &BIP16_EXCEPTION_MAINNET, 0);
        let ours = verify_tx_scripts_with_flags(prev.clone(), tx.clone(), ours_flags).is_ok();
        match compare_at_height(170_060, &BIP16_EXCEPTION_MAINNET, (prev, tx), &[]) {
            KernelCmp::Agree { accept } if accept == ours && ours == core => {}
            KernelCmp::Disagree { ours: o, core: c } if o == ours && c == core && ours != core => {}
            other => panic!("bip16 ours={ours} core={core}: {other:?}"),
        }
    }

    #[test]
    fn structured_prefix_reaches_templates() {
        let mut raw = vec![STRUCTURED];
        let flags = VERIFY_P2SH | VERIFY_WITNESS;
        raw.extend_from_slice(&flags.to_le_bytes());
        raw.push(SHAPE_DER);
        assert!(matches!(
            compare_kernel_bytes(&raw),
            Some(KernelCmp::Agree { .. } | KernelCmp::Disagree { .. })
        ));
    }

    #[test]
    fn verify_budget_rejects_only_past_one_hundred_milliseconds() {
        assert!(!verify_budget_exceeded(Duration::from_millis(0)));
        assert!(!verify_budget_exceeded(Duration::from_millis(100)));
        assert!(verify_budget_exceeded(Duration::from_millis(101)));
        assert!(!verify_budget_confirmed(
            Some(Duration::from_millis(101)),
            Some(Duration::from_millis(1)),
        ));
        assert!(verify_budget_confirmed(
            Some(Duration::from_millis(101)),
            Some(Duration::from_millis(101)),
        ));
        assert!(!verify_budget_confirmed(
            None,
            Some(Duration::from_millis(101))
        ));
    }

    #[test]
    fn legacy_half_split_is_not_executed() {
        assert_eq!(compare_kernel_bytes(&[0x1f, 0x51]), None);
    }

    #[test]
    fn raw_shape_carries_version_sequence_locktime_and_amount() {
        let flags = VERIFY_P2SH | VERIFY_WITNESS;
        let mut raw = vec![STRUCTURED];
        raw.extend_from_slice(&flags.to_le_bytes());
        raw.push(SHAPE_RAW);
        raw.extend_from_slice(&2i32.to_le_bytes());
        raw.extend_from_slice(&u32::MAX.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&5_000_000_000i64.to_le_bytes());
        raw.extend_from_slice(&0u16.to_le_bytes());
        raw.extend_from_slice(&1u16.to_le_bytes());
        raw.push(0x51);
        raw.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            compare_kernel_bytes(&raw),
            Some(KernelCmp::Agree { accept: true })
        );
    }
}
