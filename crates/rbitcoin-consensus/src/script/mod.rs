//! Pure-Rust script / signature verification.
//!
//! Verification is a pure function of `(tx, input_index, prevout TxOut)`.
//! Prevouts are resolved by connect (wave / light UTXO create_fk /
//! same-block) — not a full coins cache.

mod classify;
pub(crate) mod interpreter;
mod nested;
mod p2pkh;
mod p2tr;
mod p2wpkh;
mod p2wsh;

#[cfg(test)]
mod core_bip341;
#[cfg(test)]
mod core_fixture;
#[cfg(test)]
pub(crate) mod core_script;
#[cfg(test)]
mod core_sighash;
#[cfg(test)]
mod core_tx_vectors;
#[cfg(test)]
mod core_vectors;
#[cfg(test)]
mod tests_flag_parity;
#[cfg(test)]
mod tests_verify;

use bitcoin::hashes::Hash;
use bitcoin::{Transaction, TxOut};

use crate::block::ScriptCheckJob;
use crate::error::ConsensusError;
use classify::ScriptKind;

pub(crate) use classify::is_anyone_can_spend;

/// Verify every non-anyone-can-spend input of a script job.
///
/// One shared [`bitcoin::sighash::SighashCache`] per tx for typed paths (P2WPKH /
/// P2TR key-path / nested). Interpreter paths own a cache for the script eval so
/// multi-CHECKSIG (multisig) reuses midstate. Signet-heavy path is 1-input txs —
/// that case avoids the multi-input loop overhead.
///
/// On failure, [`ConsensusError::Script`] messages are annotated with `txid=` and
/// `vin=` so IBD logs name the failing spend (batch-first height alone is not enough).
pub(crate) fn verify_job_all_inputs(job: &ScriptCheckJob) -> Result<(), ConsensusError> {
    // JobTx may be shared wire Arc — always take &Transaction (not &JobTx).
    let tx: &Transaction = &job.tx;
    let n = job.prevouts.len();
    if n != tx.input.len() {
        return Err(ConsensusError::Script("prevout count".into()));
    }
    if n == 0 {
        return Ok(());
    }
    let mut cache = None;
    let pre = job.pre();
    let tap_spent = crypto::TapSpentHashes::default();
    if n == 1 {
        return verify_input(job, 0, tx, &mut cache, pre, &tap_spent)
            .map_err(|e| annotate_script_err(e, job, 0));
    }
    for ii in 0..n {
        verify_input(job, ii, tx, &mut cache, pre, &tap_spent)
            .map_err(|e| annotate_script_err(e, job, ii))?;
    }
    Ok(())
}

/// Append `txid=… vin=…` to script errors for operator diagnosis.
fn annotate_script_err(
    err: ConsensusError,
    job: &ScriptCheckJob,
    input_index: usize,
) -> ConsensusError {
    match err {
        ConsensusError::Script(msg) if !msg.contains("txid=") => {
            let txid = if job.txid != [0u8; 32] {
                bitcoin::Txid::from_byte_array(job.txid)
            } else {
                job.tx.compute_txid()
            };
            ConsensusError::Script(format!("{msg} txid={txid} vin={input_index}"))
        }
        other => other,
    }
}

/// Verify one input: native witness programs first, then legacy kind dispatch.
///
/// Layout (one classify, no dual typed/bare routes for the same program):
/// 1. If `witness_active` and spk is a BIP141 program → typed/unknown-version path
///    (malleation / wrong length / discourage / ACS). Never interpret as a bare script.
/// 2. Else classify once → P2PKH / P2SH / bare. Pre-segwit (`!witness_active`),
///    v0/v1 program templates fall through to the bare interpreter.
#[inline]
fn sighash_cache<'a, 't>(
    cache: &'a mut Option<bitcoin::sighash::SighashCache<&'t Transaction>>,
    tx: &'t Transaction,
) -> &'a mut bitcoin::sighash::SighashCache<&'t Transaction> {
    cache.get_or_insert_with(|| bitcoin::sighash::SighashCache::new(tx))
}

pub(crate) fn verify_input<'a>(
    job: &ScriptCheckJob,
    input_index: usize,
    tx: &'a Transaction,
    cache: &mut Option<bitcoin::sighash::SighashCache<&'a Transaction>>,
    pre: &crate::TxPrecompute,
    tap_spent: &crypto::TapSpentHashes,
) -> Result<(), ConsensusError> {
    if input_index >= job.prevouts.len() || input_index >= tx.input.len() {
        return Err(ConsensusError::Script("input index".into()));
    }
    let prevout = &job.prevouts[input_index];
    let spk = prevout.script_pubkey.as_script();
    let input = &tx.input[input_index];
    let has_witness = !input.witness.is_empty();

    if job.witness_active {
        if let Some((version, program)) = classify::witness_program(spk) {
            return verify_native_witness(
                job,
                input_index,
                tx,
                cache,
                pre,
                tap_spent,
                version,
                program,
            );
        }
    }

    let kind = classify::classify(spk);
    if job.witness_active && has_witness && !(matches!(kind, ScriptKind::P2sh) && job.bip16_active)
    {
        return Err(ConsensusError::Script("WITNESS_UNEXPECTED".into()));
    }

    match kind {
        ScriptKind::P2pkh => {
            // LOW_S / STRICTENC / NULLFAIL are interpreter policy. The fast path
            // does not apply them, so those jobs use the generic interpreter.
            if job.low_s || job.strictenc || job.nullfail {
                return verify_bare(job, input_index, tx, prevout);
            }
            // Fast path: exact `<sig> <pubkey>` scriptSig. Historical mainnet has
            // non-standard P2PKH scriptSigs that still leave a valid stack for
            // scriptPubKey (e.g. height 218596: "p2pkh scriptSig len"). Fall back
            // only for scriptSig *shape* errors (not DER/ECDSA), so bip66 failure
            // codes stay.
            match p2pkh::verify(job, input_index, tx, sighash_cache(cache, tx)) {
                Ok(()) => Ok(()),
                Err(e) if p2pkh_scriptsig_shape_error(&e) => {
                    verify_bare(job, input_index, tx, prevout)
                }
                Err(e) => Err(e),
            }
        }
        ScriptKind::P2sh => {
            // Pre-BIP16: HASH160/EQUAL is a bare script (push data, hash, equal) —
            // do **not** treat the last push as a redeemScript. Mainnet 170060.
            if !job.bip16_active {
                return verify_bare(job, input_index, tx, prevout);
            }
            let stack = nested::p2sh_script_sig_stack(job, input_index, tx)?;
            if let Some(res) = nested::try_p2sh_nested_segwit(
                job,
                input_index,
                tx,
                sighash_cache(cache, tx),
                pre,
                &stack,
            ) {
                return res;
            }
            if job.witness_active && has_witness {
                return Err(ConsensusError::Script("WITNESS_UNEXPECTED".into()));
            }
            nested::verify_p2sh_legacy(job, input_index, tx, stack)
        }
        ScriptKind::Bare | ScriptKind::P2wpkh | ScriptKind::P2wsh | ScriptKind::P2tr => {
            verify_bare(job, input_index, tx, prevout)
        }
    }
}

/// Core `IsPayToAnchor`: witness v1 program `0x4e73`.
const PAY_TO_ANCHOR_PROGRAM: [u8; 2] = [0x4e, 0x73];

/// BIP141 native witness program (any version). `scriptSig` must be empty.
///
/// Policy: a v1 32-byte program before Taproot and pay-to-anchor succeed
/// without DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, as in Core.
#[inline]
#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
fn verify_native_witness<'a>(
    job: &ScriptCheckJob,
    input_index: usize,
    tx: &'a Transaction,
    cache: &mut Option<bitcoin::sighash::SighashCache<&'a Transaction>>,
    pre: &crate::TxPrecompute,
    tap_spent: &crypto::TapSpentHashes,
    version: u8,
    program: &[u8],
) -> Result<(), ConsensusError> {
    if !tx.input[input_index].script_sig.is_empty() {
        return Err(ConsensusError::Script("WITNESS_MALLEATED".into()));
    }
    // Core runs the scriptPubKey first. A false program is EVAL_FALSE for every
    // version, including unknown ones, before anyone-can-spend success.
    if !interpreter::cast_to_bool(program) {
        return Err(ConsensusError::Script("EVAL_FALSE".into()));
    }
    match (version, program.len()) {
        (0, 20) => p2wpkh::verify(job, input_index, tx, pre),
        (0, 32) => p2wsh::verify(job, input_index, tx),
        (0, _) => Err(ConsensusError::Script(
            "WITNESS_PROGRAM_WRONG_LENGTH".into(),
        )),
        (1, 32) if job.taproot_active => {
            p2tr::verify(job, input_index, tx, sighash_cache(cache, tx), tap_spent)
        }
        (1, 32) => Ok(()),
        (1, 2) if program == PAY_TO_ANCHOR_PROGRAM => Ok(()),
        _ => {
            if job.discourage_upgradable_witness {
                return Err(ConsensusError::Script(
                    "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM".into(),
                ));
            }
            Ok(())
        }
    }
}

/// True when the P2PKH fast path failed because scriptSig is not exactly two
/// data pushes (still may be valid under the full interpreter).
fn p2pkh_scriptsig_shape_error(err: &ConsensusError) -> bool {
    match err {
        ConsensusError::Script(msg) => {
            msg == "p2pkh scriptSig len"
                || msg == "p2pkh scriptSig"
                || msg == "p2pkh scriptSig op"
                || msg == "p2pkh scriptSig unexpected op"
        }
        _ => false,
    }
}

fn verify_bare(
    job: &ScriptCheckJob,
    input_index: usize,
    tx: &Transaction,
    prevout: &TxOut,
) -> Result<(), ConsensusError> {
    // Fully run scriptSig, then scriptPubKey, sharing one stack. scriptSig is
    // not push-only in consensus for bare spends (SIGPUSHONLY is policy / BIP16-P2SH
    // only). Mainnet block 163685 has bare spends whose scriptSig runs
    // `OP_CODESEPARATOR` + `OP_CHECKMULTISIG` (sig left of codesep; pubkey script
    // after), then a pre-BIP65 `OP_NOP2`/`CLTV`+`DROP` scriptPubKey.
    let input = &tx.input[input_index];
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let ss = input.script_sig.as_script();
    if !ss.as_bytes().is_empty() {
        let ctx_sig = interpreter::EvalContext::from_job(
            job,
            tx,
            input_index,
            ss,
            interpreter::SigVersion::Base,
        );
        let _ = interpreter::eval_script(ss, &mut stack, &ctx_sig)?;
    }
    let spk = prevout.script_pubkey.as_script();
    let ctx = interpreter::EvalContext::from_job(
        job,
        tx,
        input_index,
        spk,
        interpreter::SigVersion::Base,
    );
    if interpreter::eval_script(spk, &mut stack, &ctx)? {
        if job.cleanstack {
            interpreter::require_clean_true(&stack)?;
        } else {
            interpreter::require_true_top(&stack)?;
        }
    }
    Ok(())
}

/// Shared ECDSA / secp helpers for typed paths.
pub(crate) mod crypto {
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{ecdsa, Message, PublicKey, Secp256k1, VerifyOnly};

    use crate::error::ConsensusError;

    thread_local! {
        pub static SECP: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
    }

    /// Parse DER signature + **raw** sighash type byte (as `u32`).
    ///
    /// Important: do **not** run the type through [`EcdsaSighashType::from_consensus`]
    /// before legacy `SignatureHash`. That maps `0 → SIGHASH_ALL(1)`, but mainnet
    /// has historical spends signed with hashtype **0** (block 110300 and others).
    /// Core hashes with the raw byte; we must too. (**RB-002** in
    /// `docs/rust-bitcoin-limitations.md`.)
    ///
    /// Matches Bitcoin Core:
    /// - Always parse with **lax** DER (`ecdsa_signature_parse_der_lax`). Never prefer
    ///   strict `from_der` first: for some pre-BIP66 encodings (e.g. high-bit S without
    ///   `0x00` pad, mainnet block 140493) libsecp `from_der` returns `Ok` with a
    ///   **wrong** (R,S) while `from_der_lax` recovers the OpenSSL-era values that
    ///   actually verify. (**RB-004**.)
    /// - When `strict_der` (BIP66 / `SCRIPT_VERIFY_DERSIG`), enforce
    ///   [`is_valid_signature_encoding`] on the full push (DER + hashtype) *before*
    ///   the lax parse — same split as Core's `CheckSignatureEncoding` + lax verify.
    pub fn parse_der_sig(
        sig_raw: &[u8],
        strict_der: bool,
    ) -> Result<(ecdsa::Signature, u32), ConsensusError> {
        if sig_raw.is_empty() {
            return Err(ConsensusError::Script("empty sig".into()));
        }
        if strict_der && !is_valid_signature_encoding(sig_raw) {
            return Err(ConsensusError::Script("der sig".into()));
        }
        let sighash_ty = sig_raw[sig_raw.len() - 1] as u32;
        let der = &sig_raw[..sig_raw.len() - 1];
        let sig = ecdsa::Signature::from_der_lax(der)
            .map_err(|_| ConsensusError::Script("der sig".into()))?;
        Ok((sig, sighash_ty))
    }

    /// BIP66 strict DER signature encoding.
    ///
    /// `sig` is the full scriptSig push including the trailing hashtype byte.
    /// Rejects non-minimal integer encodings (high-bit without `0x00` pad, excess
    /// leading zeros). Used only when BIP66 is active; pre-BIP66 relies on lax parse.
    pub fn is_valid_signature_encoding(sig: &[u8]) -> bool {
        // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
        // Minimum: 0x30 0x06 0x02 0x01 0x00 0x02 0x01 0x00 [ht] → 9 bytes
        // Maximum: 73 bytes (with 33-byte R/S and hashtype)
        if sig.len() < 9 || sig.len() > 73 {
            return false;
        }
        if sig[0] != 0x30 {
            return false;
        }
        // Length byte covers everything after it except hashtype.
        if sig[1] as usize != sig.len().wrapping_sub(3) {
            return false;
        }
        if sig[2] != 0x02 {
            return false;
        }
        let len_r = sig[3] as usize;
        if len_r == 0 {
            return false;
        }
        if 5 + len_r >= sig.len() {
            return false;
        }
        if sig[4 + len_r] != 0x02 {
            return false;
        }
        let len_s = sig[5 + len_r] as usize;
        if len_s == 0 {
            return false;
        }
        if len_r + len_s + 7 != sig.len() {
            return false;
        }
        if sig[4] & 0x80 != 0 {
            return false;
        }
        if len_r > 1 && sig[4] == 0x00 && (sig[5] & 0x80) == 0 {
            return false;
        }
        let s0 = 6 + len_r;
        if sig[s0] & 0x80 != 0 {
            return false;
        }
        if len_s > 1 && sig[s0] == 0x00 && (sig[s0 + 1] & 0x80) == 0 {
            return false;
        }
        true
    }

    pub fn parse_pubkey(raw: &[u8]) -> Result<PublicKey, ConsensusError> {
        PublicKey::from_slice(raw).map_err(|_| ConsensusError::Script("pubkey".into()))
    }

    /// True when S ≤ n/2 (already low).
    ///
    /// Compares compact form before/after libsecp `normalize_s` (this crate's
    /// `normalize_s` returns `()`, not a bool).
    pub fn is_low_der_s(sig: &ecdsa::Signature) -> bool {
        let before = sig.serialize_compact();
        let mut n = *sig;
        n.normalize_s();
        before == n.serialize_compact()
    }

    /// Base hashtype in {ALL,NONE,SINGLE}, optional ACP.
    pub fn is_defined_hashtype(sig_raw: &[u8]) -> bool {
        if sig_raw.is_empty() {
            return false;
        }
        let ht = sig_raw[sig_raw.len() - 1];
        let base = ht & !0x80; // strip SIGHASH_ANYONECANPAY
        (1..=3).contains(&base) // ALL=1 NONE=2 SINGLE=3
    }

    /// STRICTENC: 02/03+32 or 04+64. Hybrid 06/07 keys are rejected.
    pub fn is_compressed_or_uncompressed_pubkey(pk: &[u8]) -> bool {
        match pk.first() {
            Some(0x02 | 0x03) if pk.len() == 33 => true,
            Some(0x04) if pk.len() == 65 => true,
            _ => false,
        }
    }

    /// WITNESS_PUBKEYTYPE: 02/03 + 32 bytes only.
    pub fn is_compressed_pubkey(pk: &[u8]) -> bool {
        matches!(pk.first(), Some(0x02 | 0x03)) && pk.len() == 33
    }

    fn sighash_midstate(h: Option<[u8; 32]>) -> Result<[u8; 32], ConsensusError> {
        h.ok_or_else(|| ConsensusError::Script("invariant: sighash midstate missing".into()))
    }

    /// BIP143 signature hash with **raw** `nHashType` (last byte of the sig push).
    ///
    /// `script_code` is the BIP143 scriptCode (for P2WPKH: the
    /// `OP_DUP OP_HASH160 <keyhash> OP_EQUALVERIFY OP_CHECKSIG` template; for
    /// P2WSH: the witness script).
    pub fn bip143_signature_hash(
        tx: &bitcoin::Transaction,
        input_index: usize,
        script_code: &bitcoin::Script,
        amount: bitcoin::Amount,
        raw_ty: u32,
        pre: &crate::TxPrecompute,
    ) -> Result<[u8; 32], ConsensusError> {
        use bitcoin::consensus::Encodable;
        use bitcoin::hashes::{sha256d, Hash, HashEngine};
        use bitcoin::sighash::EcdsaSighashType;

        if input_index >= tx.input.len() {
            return Err(ConsensusError::Script("bip143 input index".into()));
        }
        use EcdsaSighashType::*;
        let mapped = EcdsaSighashType::from_consensus(raw_ty);
        // `split_anyonecanpay_flag` is crate-private in rust-bitcoin 0.32.
        let anyone_can_pay = matches!(
            mapped,
            AllPlusAnyoneCanPay | NonePlusAnyoneCanPay | SinglePlusAnyoneCanPay
        );
        let base = match mapped {
            None | NonePlusAnyoneCanPay => None,
            Single | SinglePlusAnyoneCanPay => Single,
            _ => All,
        };
        let zero = [0u8; 32];

        let hash_prevouts: [u8; 32] = if !anyone_can_pay {
            sighash_midstate(pre.hash_prevouts())?
        } else {
            zero
        };

        let hash_sequence: [u8; 32] = if !anyone_can_pay && base != Single && base != None {
            sighash_midstate(pre.hash_sequence())?
        } else {
            zero
        };

        let hash_outputs: [u8; 32] = if base != Single && base != None {
            sighash_midstate(pre.hash_outputs())?
        } else if base == Single && input_index < tx.output.len() {
            let mut eng = sha256d::Hash::engine();
            tx.output[input_index]
                .consensus_encode(&mut eng)
                .map_err(|_| ConsensusError::Script("bip143 single output".into()))?;
            sha256d::Hash::from_engine(eng).to_byte_array()
        } else {
            zero
        };

        let mut eng = sha256d::Hash::engine();
        tx.version
            .consensus_encode(&mut eng)
            .map_err(|_| ConsensusError::Script("bip143 version".into()))?;
        eng.input(&hash_prevouts);
        eng.input(&hash_sequence);
        {
            let txin = &tx.input[input_index];
            txin.previous_output
                .consensus_encode(&mut eng)
                .map_err(|_| ConsensusError::Script("bip143 outpoint".into()))?;
            script_code
                .consensus_encode(&mut eng)
                .map_err(|_| ConsensusError::Script("bip143 scriptCode".into()))?;
            amount
                .consensus_encode(&mut eng)
                .map_err(|_| ConsensusError::Script("bip143 amount".into()))?;
            txin.sequence
                .consensus_encode(&mut eng)
                .map_err(|_| ConsensusError::Script("bip143 nSequence".into()))?;
        }
        eng.input(&hash_outputs);
        tx.lock_time
            .consensus_encode(&mut eng)
            .map_err(|_| ConsensusError::Script("bip143 locktime".into()))?;
        // Core: raw nHashType as uint32 LE — not the normalized enum value.
        eng.input(&raw_ty.to_le_bytes());
        Ok(sha256d::Hash::from_engine(eng).to_byte_array())
    }

    /// P2WPKH BIP143 hash: `script_pubkey` is native spk **or** nested redeem (`00 14 <20>`).
    ///
    /// Fast path: when `raw_ty` round-trips through [`EcdsaSighashType`] (standard
    /// 0x01/02/03/81/82/83), use rust-bitcoin's [`SighashCache`] midstate
    /// (hashPrevouts/hashSequence/hashOutputs once per tx). Slow path: non-standard
    /// raw types (e.g. mainnet `0x65`) need our raw-uint32 encoder.
    pub fn bip143_p2wpkh_signature_hash(
        tx: &bitcoin::Transaction,
        input_index: usize,
        script_pubkey: &bitcoin::Script,
        amount: bitcoin::Amount,
        raw_ty: u32,
        pre: &crate::TxPrecompute,
    ) -> Result<[u8; 32], ConsensusError> {
        let script_code = script_pubkey
            .p2wpkh_script_code()
            .ok_or_else(|| ConsensusError::Script("bip143 not p2wpkh".into()))?;
        bip143_signature_hash(
            tx,
            input_index,
            script_code.as_script(),
            amount,
            raw_ty,
            pre,
        )
    }

    /// P2WSH / WitnessV0 BIP143 using [`crate::TxPrecompute`] midstates.
    pub fn bip143_p2wsh_signature_hash(
        tx: &bitcoin::Transaction,
        input_index: usize,
        witness_script: &bitcoin::Script,
        amount: bitcoin::Amount,
        raw_ty: u32,
        pre: &crate::TxPrecompute,
    ) -> Result<[u8; 32], ConsensusError> {
        bip143_signature_hash(tx, input_index, witness_script, amount, raw_ty, pre)
    }

    /// Core `PrecomputedTransactionData` spent-output half: BIP341
    /// `sha_amounts` and `sha_scriptpubkeys`. One per tx, filled by the first
    /// tapscript signature check that commits to the spent outputs.
    #[derive(Default)]
    pub struct TapSpentHashes(std::cell::OnceCell<[[u8; 32]; 2]>);

    impl TapSpentHashes {
        fn get(
            &self,
            pre: &crate::TxPrecompute,
            prevouts: &[bitcoin::TxOut],
        ) -> Result<[[u8; 32]; 2], ConsensusError> {
            if let Some(hashes) = self.0.get() {
                return Ok(*hashes);
            }
            let mut spent = pre.clone();
            spent.finish_spent(prevouts);
            let hashes = [
                sighash_midstate(spent.sha_amounts)?,
                sighash_midstate(spent.sha_scriptpubkeys)?,
            ];
            Ok(*self.0.get_or_init(|| hashes))
        }
    }

    /// Core `ScriptExecutionData` for one tapscript spend: the BIP341/342
    /// sighash inputs that do not change between its signature opcodes.
    ///
    /// CPU trade: the tapleaf and annex hashes come in once per script-path
    /// input, the SIGHASH_SINGLE output hash is filled on first use, and the
    /// spent-output hashes once per tx through [`TapSpentHashes`]. Each
    /// signature opcode then hashes a fixed-size message. Rehashing per
    /// opcode is quadratic, because the validation weight budget grows with
    /// the same witness bytes; rehashing the spent outputs per input is
    /// quadratic in the input count.
    pub struct TapscriptExecData<'a> {
        tx: &'a bitcoin::Transaction,
        input_index: usize,
        prevouts: &'a [bitcoin::TxOut],
        pre: &'a crate::TxPrecompute,
        spent: &'a TapSpentHashes,
        tapleaf_hash: bitcoin::TapLeafHash,
        annex_hash: Option<[u8; 32]>,
        single_output_hash: std::cell::OnceCell<Option<[u8; 32]>>,
    }

    impl<'a> TapscriptExecData<'a> {
        /// `annex` is the BIP341 annex including its `0x50` tag. `pre` and
        /// `spent` belong to `tx`.
        pub fn new(
            tx: &'a bitcoin::Transaction,
            input_index: usize,
            prevouts: &'a [bitcoin::TxOut],
            pre: &'a crate::TxPrecompute,
            spent: &'a TapSpentHashes,
            tapleaf_hash: bitcoin::TapLeafHash,
            annex: Option<&[u8]>,
        ) -> Self {
            use bitcoin::consensus::encode::VarInt;
            use bitcoin::consensus::Encodable;
            use bitcoin::hashes::{sha256, HashEngine};

            let annex_hash = annex.map(|annex| {
                let mut eng = sha256::Hash::engine();
                VarInt(annex.len() as u64)
                    .consensus_encode(&mut eng)
                    .expect("hash engines do not error");
                eng.input(annex);
                sha256::Hash::from_engine(eng).to_byte_array()
            });
            Self {
                tx,
                input_index,
                prevouts,
                pre,
                spent,
                tapleaf_hash,
                annex_hash,
                single_output_hash: std::cell::OnceCell::new(),
            }
        }

        /// BIP341 signature message hash with BIP342 extension (Core
        /// `SignatureHashSchnorr`, `SigVersion::TAPSCRIPT`, key version 0).
        pub fn signature_hash(
            &self,
            hash_type: bitcoin::sighash::TapSighashType,
            codeseparator_pos: u32,
        ) -> Result<[u8; 32], ConsensusError> {
            use bitcoin::consensus::Encodable;
            use bitcoin::hashes::{sha256, HashEngine};
            use bitcoin::sighash::TapSighash;

            const SIGHASH_ALL: u8 = 0x01;
            const SIGHASH_SINGLE: u8 = 0x03;
            const SIGHASH_ANYONECANPAY: u8 = 0x80;
            const EXT_FLAG_TAPSCRIPT: u8 = 1;
            const KEY_VERSION: u8 = 0;

            let (tx, input_index, prevouts, pre) =
                (self.tx, self.input_index, self.prevouts, self.pre);
            let (Some(txin), Some(spent_output)) =
                (tx.input.get(input_index), prevouts.get(input_index))
            else {
                return Err(ConsensusError::Script("tapscript sighash input".into()));
            };
            if prevouts.len() != tx.input.len() {
                return Err(ConsensusError::Script("tapscript sighash prevouts".into()));
            }
            let hash_type = hash_type as u8;
            let output_type = match hash_type {
                0 => SIGHASH_ALL,
                ty => ty & 0x03,
            };
            let anyone_can_pay = hash_type & SIGHASH_ANYONECANPAY != 0;

            let mut eng = TapSighash::engine();
            eng.input(&[0, hash_type]);
            tx.version
                .consensus_encode(&mut eng)
                .expect("hash engines do not error");
            tx.lock_time
                .consensus_encode(&mut eng)
                .expect("hash engines do not error");
            if !anyone_can_pay {
                let [sha_amounts, sha_scriptpubkeys] = self.spent.get(pre, prevouts)?;
                eng.input(&sighash_midstate(pre.sha_prevouts)?);
                eng.input(&sha_amounts);
                eng.input(&sha_scriptpubkeys);
                eng.input(&sighash_midstate(pre.sha_sequences)?);
            }
            if output_type == SIGHASH_ALL {
                eng.input(&sighash_midstate(pre.sha_outputs)?);
            }
            eng.input(&[(EXT_FLAG_TAPSCRIPT << 1) | u8::from(self.annex_hash.is_some())]);
            if anyone_can_pay {
                txin.previous_output
                    .consensus_encode(&mut eng)
                    .expect("hash engines do not error");
                spent_output
                    .consensus_encode(&mut eng)
                    .expect("hash engines do not error");
                txin.sequence
                    .consensus_encode(&mut eng)
                    .expect("hash engines do not error");
            } else {
                eng.input(&(input_index as u32).to_le_bytes());
            }
            if let Some(annex_hash) = &self.annex_hash {
                eng.input(annex_hash);
            }
            if output_type == SIGHASH_SINGLE {
                let output_hash = self.single_output_hash.get_or_init(|| {
                    tx.output.get(input_index).map(|out| {
                        let mut out_eng = sha256::Hash::engine();
                        out.consensus_encode(&mut out_eng)
                            .expect("hash engines do not error");
                        sha256::Hash::from_engine(out_eng).to_byte_array()
                    })
                });
                let output_hash = output_hash
                    .ok_or_else(|| ConsensusError::Script("tapscript sighash single".into()))?;
                eng.input(&output_hash);
            }
            eng.input(self.tapleaf_hash.as_byte_array());
            eng.input(&[KEY_VERSION]);
            eng.input(&codeseparator_pos.to_le_bytes());
            Ok(TapSighash::from_engine(eng).to_byte_array())
        }
    }

    /// Verify ECDSA under **Bitcoin consensus** rules.
    ///
    /// libsecp256k1 rejects high-S signatures, but high-S has never been a
    /// consensus failure on Bitcoin (BIP146 unactivated). Bitcoin Core normalizes
    /// S before verify (`ecdsa_signature_normalize`) — we do the same so early
    /// mainnet P2PK spends (e.g. block 183) accept.
    pub fn verify_ecdsa(msg_bytes: [u8; 32], sig: &ecdsa::Signature, pubkey: &PublicKey) -> bool {
        let msg = Message::from_digest(msg_bytes);
        let mut normalized = *sig;
        normalized.normalize_s();
        SECP.with(|secp| secp.verify_ecdsa(&msg, &normalized, pubkey).is_ok())
    }

    pub fn hash160(data: &[u8]) -> [u8; 20] {
        use bitcoin::hashes::hash160;
        *hash160::Hash::hash(data).as_byte_array()
    }

    pub fn sha256(data: &[u8]) -> [u8; 32] {
        use bitcoin::hashes::sha256;
        *sha256::Hash::hash(data).as_byte_array()
    }

    pub fn sha1(data: &[u8]) -> [u8; 20] {
        use bitcoin_hashes::Hash as _;
        *bitcoin_hashes::sha1::Hash::hash(data).as_byte_array()
    }

    #[cfg(test)]
    mod der_tests {
        use super::*;

        fn valid_der_sig() -> Vec<u8> {
            // Minimal valid-shaped DER + SIGHASH_ALL
            // 30 06 02 01 01 02 01 01 01
            vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]
        }

        #[test]
        fn strictenc_pubkey_and_hashtype_helpers() {
            // Compressed / uncompressed only — hybrid 06/07 rejected.
            assert!(is_compressed_or_uncompressed_pubkey(&[0x02; 33]));
            assert!(is_compressed_or_uncompressed_pubkey(&[0x03; 33]));
            let mut uncomp = vec![0x04];
            uncomp.extend_from_slice(&[0x11; 64]);
            assert!(is_compressed_or_uncompressed_pubkey(&uncomp));
            let mut hybrid = vec![0x06];
            hybrid.extend_from_slice(&[0x11; 64]);
            assert!(!is_compressed_or_uncompressed_pubkey(&hybrid));
            assert!(!is_compressed_or_uncompressed_pubkey(&[]));
            assert!(!is_compressed_or_uncompressed_pubkey(&[0x02; 32]));

            assert!(is_defined_hashtype(&[0x30, 0x01])); // ALL
            assert!(is_defined_hashtype(&[0x30, 0x02])); // NONE
            assert!(is_defined_hashtype(&[0x30, 0x03])); // SINGLE
            assert!(is_defined_hashtype(&[0x30, 0x81])); // ALL|ACP
            assert!(!is_defined_hashtype(&[0x30, 0x00]));
            assert!(!is_defined_hashtype(&[0x30, 0x04]));
            assert!(!is_defined_hashtype(&[]));
        }

        #[test]
        fn bip66_encoding_edge_cases() {
            assert!(!is_valid_signature_encoding(&[]));
            assert!(!is_valid_signature_encoding(&[0x30; 8])); // too short
            assert!(!is_valid_signature_encoding(&[0x30; 74])); // too long
            let mut bad = valid_der_sig();
            bad[0] = 0x31;
            assert!(!is_valid_signature_encoding(&bad));
            // wrong total length byte
            let mut bad = valid_der_sig();
            bad[1] = 0x05;
            assert!(!is_valid_signature_encoding(&bad));
            // R not INT
            let mut bad = valid_der_sig();
            bad[2] = 0x03;
            assert!(!is_valid_signature_encoding(&bad));
            // zero-length R
            assert!(!is_valid_signature_encoding(&[
                0x30, 0x06, 0x02, 0x00, 0x02, 0x01, 0x01, 0x01
            ]));
            // R high bit set (negative)
            let neg = vec![0x30, 0x07, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01, 0x01];
            assert!(!is_valid_signature_encoding(&neg));
            // excess leading zero on R
            let pad = vec![0x30, 0x08, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01, 0x01];
            assert!(!is_valid_signature_encoding(&pad));
            // S high bit
            let sneg = vec![0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x80, 0x01];
            assert!(!is_valid_signature_encoding(&sneg));
            // excess leading zero on S
            let spad = vec![0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x01, 0x01];
            assert!(!is_valid_signature_encoding(&spad));
            // zero-length S
            assert!(!is_valid_signature_encoding(&[
                0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x00, 0x01
            ]));
            // S marker wrong
            let mut sm = valid_der_sig();
            sm[4] = 0x03; // after R len=1 at [3]=1, S tag at index 4
                          // structure: [0]=30 [1]=06 [2]=02 [3]=01 [4]=R [5]=02 [6]=01 [7]=S [8]=ht
                          // Actually valid_der is 30 06 02 01 01 02 01 01 01 so S tag at [5]
            let mut sm = valid_der_sig();
            sm[5] = 0x03;
            assert!(!is_valid_signature_encoding(&sm));

            assert!(is_valid_signature_encoding(&valid_der_sig()));
            let _ = (neg, pad, sneg, spad);
        }

        #[test]
        fn parse_der_empty_and_strict() {
            assert!(parse_der_sig(&[], true).is_err());
            // non-BIP66 but lax may still fail parse — just exercise strict reject
            let bad = vec![0x30, 0x01, 0x00];
            assert!(parse_der_sig(&bad, true).is_err());
        }
    }
}

#[cfg(test)]
mod verify_routing_tests {
    use super::*;
    use crate::block::ScriptCheckJob;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

    fn witness_job(spk: Vec<u8>, script_sig: Vec<u8>, witness: Vec<Vec<u8>>) -> ScriptCheckJob {
        let refs: Vec<&[u8]> = witness.iter().map(|v| v.as_slice()).collect();
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(script_sig),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::from_slice(&refs),
            }],
            output: vec![],
        };
        ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(spk),
            }],
            tx: crate::block::JobTx::owned(tx),
            flags: crate::block::ScriptVerifyFlags {
                bip65_active: true,
                bip112_active: true,
                bip66_active: true,
                bip16_active: true,
                taproot_active: true,
                minimal_if: false,
                nullfail: false,
                low_s: false,
                strictenc: false,
                null_dummy: false,
                minimal_data: false,
                witness_pubkeytype: false,
                witness_active: true,
                discourage_upgradable_witness: false,
                const_scriptcode: false,
                cleanstack: false,
            },
            pre: std::sync::OnceLock::new(),
        }
    }

    #[test]
    fn false_witness_program_is_eval_false() {
        let native = witness_job(vec![0x52, 0x02, 0x00, 0x00], vec![], vec![]);
        let err = verify_job_all_inputs(&native).expect_err("zero program");
        assert!(format!("{err}").contains("EVAL_FALSE"), "{err}");

        let neg = witness_job(vec![0x60, 0x03, 0x00, 0x00, 0x80], vec![], vec![]);
        let err = verify_job_all_inputs(&neg).expect_err("negative zero");
        assert!(format!("{err}").contains("EVAL_FALSE"), "{err}");

        let live = witness_job(vec![0x52, 0x02, 0x00, 0x01], vec![], vec![]);
        verify_job_all_inputs(&live).expect("nonzero unknown version");

        let redeem = vec![0x52, 0x02, 0x00, 0x00];
        let hash = super::crypto::hash160(&redeem);
        let mut spk = vec![0xa9, 0x14];
        spk.extend_from_slice(hash.as_slice());
        spk.push(0x87);
        let mut script_sig = vec![redeem.len() as u8];
        script_sig.extend_from_slice(&redeem);
        let nested = witness_job(spk, script_sig, vec![]);
        let err = verify_job_all_inputs(&nested).expect_err("p2sh zero program");
        assert!(format!("{err}").contains("EVAL_FALSE"), "{err}");
    }

    #[test]
    fn prevout_count_must_match_inputs() {
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![],
        };
        let job = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![],
            tx: crate::block::JobTx::owned(tx),
            flags: crate::block::ScriptVerifyFlags::buried(true, true, true, true, true),
            pre: std::sync::OnceLock::new(),
        };
        let err = verify_job_all_inputs(&job).expect_err("empty prevouts");
        assert!(format!("{err}").contains("prevout count"), "{err}");
    }

    #[test]
    fn empty_prevouts_and_index_errors() {
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let job = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![],
            tx: crate::block::JobTx::owned(tx.clone()),
            flags: crate::block::ScriptVerifyFlags {
                bip65_active: true,
                bip112_active: true,
                bip66_active: true,
                bip16_active: true,
                taproot_active: true,
                minimal_if: false,
                nullfail: false,
                low_s: false,
                strictenc: false,
                null_dummy: false,
                minimal_data: false,
                witness_pubkeytype: false,
                witness_active: true,
                discourage_upgradable_witness: false,
                const_scriptcode: false,
                cleanstack: false,
            },
            pre: std::sync::OnceLock::new(),
        };
        assert!(verify_job_all_inputs(&job).is_ok());

        let job2 = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
            tx: crate::block::JobTx::owned(Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![],
                output: vec![],
            }),
            flags: crate::block::ScriptVerifyFlags {
                bip65_active: true,
                bip112_active: true,
                bip66_active: true,
                bip16_active: true,
                taproot_active: true,
                minimal_if: false,
                nullfail: false,
                low_s: false,
                strictenc: false,
                null_dummy: false,
                minimal_data: false,
                witness_pubkeytype: false,
                witness_active: true,
                discourage_upgradable_witness: false,
                const_scriptcode: false,
                cleanstack: false,
            },
            pre: std::sync::OnceLock::new(),
        };
        let cache = bitcoin::sighash::SighashCache::new(&*job2.tx);
        let pre = crate::TxPrecompute::from_tx(&job2.tx);
        let mut cache_slot = Some(cache);
        let tap_spent = crypto::TapSpentHashes::default();
        assert!(verify_input(&job2, 0, &job2.tx, &mut cache_slot, &pre, &tap_spent).is_err());
    }

    #[test]
    fn verify_job_uses_stashed_pre_for_bip143() {
        use bitcoin::sighash::{EcdsaSighashType, SighashCache};
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0x11; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[vec![0x30; 71], vec![0x51]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let pre = std::sync::Arc::new(crate::TxPrecompute::from_tx(&tx));
        let wscript = bitcoin::script::Script::from_bytes(&[0x51]);
        let ours = crypto::bip143_p2wsh_signature_hash(
            &tx,
            0,
            wscript,
            Amount::from_sat(50_000),
            0x01,
            pre.as_ref(),
        )
        .unwrap();
        let mut cache = SighashCache::new(&tx);
        let theirs = cache
            .p2wsh_signature_hash(0, wscript, Amount::from_sat(50_000), EcdsaSighashType::All)
            .unwrap()
            .to_byte_array();
        assert_eq!(ours, theirs);
        let pres: std::sync::Arc<[crate::TxPrecompute]> = std::sync::Arc::from([(*pre).clone()]);
        let job = ScriptCheckJob::with_txid(
            pre.txid,
            vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(
                    vec![0x00, 0x20].into_iter().chain([0; 32]).collect(),
                ),
            }],
            tx,
            crate::block::ScriptVerifyFlags::buried(true, true, true, true, true),
        )
        .with_pre_slice(pres, 0);
        assert_eq!(job.pre().txid, job.txid);
    }

    #[test]
    fn from_tx_connect_bip143_fails_closed_without_midstate() {
        let tx = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0x11; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[vec![0x30; 71], vec![0x02; 33]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let pre = crate::TxPrecompute::from_tx_connect(&tx);
        let wscript = bitcoin::script::Script::from_bytes(&[0x51]);
        let amt = Amount::from_sat(50_000);
        let err = crypto::bip143_p2wsh_signature_hash(&tx, 0, wscript, amt, 0x01, &pre)
            .expect_err("connect-only precompute must not sighash");
        let msg = err.to_string();
        assert!(
            msg.contains("invariant: sighash midstate missing"),
            "got: {msg}"
        );
    }

    #[test]
    fn annotate_preserves_non_script_and_existing_txid() {
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([2; 32]),
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
        let job = ScriptCheckJob::new(
            vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
            tx,
            crate::block::ScriptVerifyFlags::buried(true, true, true, true, true),
        );
        let e = annotate_script_err(ConsensusError::MissingPrevout, &job, 0);
        assert!(matches!(e, ConsensusError::MissingPrevout));
        let e2 = annotate_script_err(
            ConsensusError::Script("already txid=abc vin=0".into()),
            &job,
            3,
        );
        match e2 {
            ConsensusError::Script(m) => assert!(m.contains("already txid=")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn taproot_inactive_is_anyone_can_spend() {
        let mut spk = vec![0x51, 0x20];
        spk.extend([0u8; 31]);
        spk.push(1);
        let job = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(spk),
            }],
            tx: crate::block::JobTx::owned(Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::from_byte_array([3; 32]),
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
            }),
            flags: crate::block::ScriptVerifyFlags {
                bip65_active: true,
                bip112_active: true,
                bip66_active: true,
                bip16_active: true,
                taproot_active: false,
                minimal_if: false,
                nullfail: false,
                low_s: false,
                strictenc: false,
                null_dummy: false,
                minimal_data: false,
                witness_pubkeytype: false,
                witness_active: true,
                discourage_upgradable_witness: false,
                const_scriptcode: false,
                cleanstack: false,
            },
            pre: std::sync::OnceLock::new(),
        };
        verify_job_all_inputs(&job).expect("pre-taproot v1 ACS");
    }

    #[test]
    fn p2pkh_shape_error_detection() {
        assert!(p2pkh_scriptsig_shape_error(&ConsensusError::Script(
            "p2pkh scriptSig len".into()
        )));
        assert!(p2pkh_scriptsig_shape_error(&ConsensusError::Script(
            "p2pkh scriptSig".into()
        )));
        assert!(p2pkh_scriptsig_shape_error(&ConsensusError::Script(
            "p2pkh scriptSig op".into()
        )));
        assert!(p2pkh_scriptsig_shape_error(&ConsensusError::Script(
            "p2pkh scriptSig unexpected op".into()
        )));
        assert!(!p2pkh_scriptsig_shape_error(&ConsensusError::Script(
            "p2pkh ecdsa".into()
        )));
        assert!(!p2pkh_scriptsig_shape_error(
            &ConsensusError::MissingPrevout
        ));
    }

    #[test]
    fn bip143_sighash_arms_single_acp_and_p2wsh() {
        use bitcoin::script::Script;
        use bitcoin::Amount;

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::from_byte_array([1; 32]),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::from_byte_array([2; 32]),
                        vout: 1,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::from_consensus(1),
                    witness: Witness::new(),
                },
            ],
            output: vec![
                TxOut {
                    value: Amount::from_sat(1000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
                TxOut {
                    value: Amount::from_sat(2000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x52]),
                },
            ],
        };
        let sc = Script::from_bytes(&[0x51]);
        let amt = Amount::from_sat(50_000);

        // Bad index.
        let pre = crate::TxPrecompute::from_tx(&tx);
        assert!(crypto::bip143_signature_hash(&tx, 9, sc, amt, 0x01, &pre).is_err());

        // All / Single / None + AnyoneCanPay variants.
        for ty in [0x01u32, 0x02, 0x03, 0x81, 0x82, 0x83] {
            let h = crypto::bip143_signature_hash(&tx, 0, sc, amt, ty, &pre).expect("sighash");
            assert_ne!(h, [0u8; 32]);
        }
        // Single at index with matching output (input 1 → output 1).
        let h_single = crypto::bip143_signature_hash(&tx, 1, sc, amt, 0x03, &pre).unwrap();
        // Single with no matching output (only 2 outs; index 1 ok; use 1-input for zero outputs arm).
        let tx1 = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![tx.input[0].clone()],
            output: vec![],
        };
        let pre1 = crate::TxPrecompute::from_tx(&tx1);
        let h_none_out = crypto::bip143_signature_hash(&tx1, 0, sc, amt, 0x03, &pre1).unwrap();
        assert_ne!(h_single, h_none_out);

        // Non-standard raw type 0x65 uses the same midstates + raw nHashType.
        let wscript = Script::from_bytes(&[0x51]);
        let h_fast = crypto::bip143_p2wsh_signature_hash(&tx, 0, wscript, amt, 0x01, &pre).unwrap();
        let h_slow = crypto::bip143_p2wsh_signature_hash(&tx, 0, wscript, amt, 0x65, &pre).unwrap();
        assert_ne!(h_fast, [0u8; 32]);
        assert_ne!(h_slow, [0u8; 32]);
        // Standard and non-standard types must differ (raw_ty in digest).
        assert_ne!(h_fast, h_slow);
    }

    /// Tapscript sighash from cached leaf / annex / output hashes matches
    /// rust-bitcoin's `taproot_signature_hash` on every BIP341 hash type.
    #[test]
    fn tapscript_sighash_matches_rust_bitcoin_on_every_hash_type() {
        use bitcoin::sighash::{Annex, Prevouts, SighashCache, TapSighashType};
        use bitcoin::taproot::LeafVersion;
        use bitcoin::TapLeafHash;

        let outpoint = |n: u8| OutPoint {
            txid: bitcoin::Txid::from_byte_array([n; 32]),
            vout: u32::from(n),
        };
        let input = |n: u8| TxIn {
            previous_output: outpoint(n),
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xffff_fff0 - u32::from(n)),
            witness: Witness::new(),
        };
        let output = |n: u8| TxOut {
            value: Amount::from_sat(1_000 * u64::from(n)),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51; usize::from(n)]),
        };
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::from_consensus(500),
            input: vec![input(1), input(2), input(3)],
            output: vec![output(4), output(5)],
        };
        let prevouts = vec![output(6), output(7), output(8)];
        let pre = crate::TxPrecompute::from_tx(&tx);
        let leaf = ScriptBuf::from_bytes(vec![0x51, 0x75, 0x51]);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let annex_bytes = [0x50, 0x01, 0x02];
        let types = [
            TapSighashType::Default,
            TapSighashType::All,
            TapSighashType::None,
            TapSighashType::Single,
            TapSighashType::AllPlusAnyoneCanPay,
            TapSighashType::NonePlusAnyoneCanPay,
            TapSighashType::SinglePlusAnyoneCanPay,
        ];

        let tap_spent = crypto::TapSpentHashes::default();
        for annex in [None, Some(&annex_bytes[..])] {
            for input_index in 0..tx.input.len() {
                let exec = crypto::TapscriptExecData::new(
                    &tx,
                    input_index,
                    &prevouts,
                    &pre,
                    &tap_spent,
                    leaf_hash,
                    annex,
                );
                for ty in types {
                    for codesep in [0xFFFF_FFFF, 0, 7] {
                        let ours = exec.signature_hash(ty, codesep);
                        let oracle = SighashCache::new(&tx).taproot_signature_hash(
                            input_index,
                            &Prevouts::All(&prevouts),
                            annex.map(|a| Annex::new(a).unwrap()),
                            Some((leaf_hash, codesep)),
                            ty,
                        );
                        match oracle {
                            Ok(h) => assert_eq!(
                                ours.expect("ours"),
                                h.to_byte_array(),
                                "vin={input_index} {ty:?} codesep={codesep} annex={annex:?}"
                            ),
                            Err(_) => assert!(
                                ours.is_err(),
                                "vin={input_index} {ty:?}: rust-bitcoin rejects, ours accepts"
                            ),
                        }
                    }
                }
            }
        }

        let short = &prevouts[..2];
        let tap_spent = crypto::TapSpentHashes::default();
        let exec = crypto::TapscriptExecData::new(&tx, 0, short, &pre, &tap_spent, leaf_hash, None);
        assert!(exec.signature_hash(TapSighashType::Default, 0).is_err());
    }

    #[test]
    fn bip16_inactive_treats_p2sh_as_bare() {
        // P2SH template spent as bare HASH160/EQUAL when bip16 off.
        let mut p2sh = vec![0xa9, 0x14];
        p2sh.extend([0u8; 20]);
        p2sh.push(0x87);
        // scriptSig that just pushes 20 zero bytes (equal fails — but exercises bare path)
        let mut ss = vec![0x14];
        ss.extend([0u8; 20]);
        let job = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(p2sh),
            }],
            tx: crate::block::JobTx::owned(Transaction {
                version: bitcoin::transaction::Version::ONE,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::from_byte_array([4; 32]),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::from_bytes(ss),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            }),
            flags: crate::block::ScriptVerifyFlags {
                bip65_active: false,
                bip112_active: false,
                bip66_active: false,
                bip16_active: false,
                taproot_active: false,
                minimal_if: false,
                nullfail: false,
                low_s: false,
                strictenc: false,
                null_dummy: false,
                minimal_data: false,
                witness_pubkeytype: false,
                witness_active: true,
                discourage_upgradable_witness: false,
                const_scriptcode: false,
                cleanstack: false,
            },
            pre: std::sync::OnceLock::new(),
        };
        // Bare HASH160 equal of zeros vs hash160([]) — should fail script, not p2sh redeem.
        let err = verify_job_all_inputs(&job).unwrap_err();
        assert!(matches!(err, ConsensusError::Script(_)));
    }
}
