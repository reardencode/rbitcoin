//! Pure-Rust script / signature verification.
//!
//! Verification is a pure function of `(tx, input_index, prevout TxOut)`.
//! Prevouts are resolved by connect (wave / light UTXO create_fk /
//! same-block) — not a full coins cache.

#[doc(hidden)]
pub mod classify;
#[doc(hidden)]
pub mod interpreter;
#[doc(hidden)]
pub mod nested;
#[doc(hidden)]
pub mod p2pkh;
#[doc(hidden)]
pub mod p2tr;
#[doc(hidden)]
pub mod p2wpkh;
#[doc(hidden)]
pub mod p2wsh;

#[cfg(feature = "corpus")]
pub mod core_script;

use bitcoin::hashes::Hash;
use bitcoin::Transaction;

use crate::block::ScriptCheckJob;
use crate::error::ConsensusError;
use classify::ScriptKind;

pub use classify::is_anyone_can_spend;

/// Verify every non-anyone-can-spend input of a script job.
///
/// One shared [`bitcoin::sighash::SighashCache`] per tx for typed paths (P2WPKH /
/// nested). P2TR hashes borrowed prevout scripts. Interpreter paths own a cache for the script eval so
/// multi-CHECKSIG (multisig) reuses midstate. Signet-heavy path is 1-input txs —
/// that case avoids the multi-input loop overhead.
///
/// On failure, [`ConsensusError::Script`] messages are annotated with `txid=` and
/// `vin=` so IBD logs name the failing spend (batch-first height alone is not enough).
pub fn verify_job_all_inputs(job: &ScriptCheckJob) -> Result<(), ConsensusError> {
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
#[doc(hidden)]
pub fn annotate_script_err(
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
#[doc(hidden)]
pub fn sighash_cache<'a, 't>(
    cache: &'a mut Option<bitcoin::sighash::SighashCache<&'t Transaction>>,
    tx: &'t Transaction,
) -> &'a mut bitcoin::sighash::SighashCache<&'t Transaction> {
    cache.get_or_insert_with(|| bitcoin::sighash::SighashCache::new(tx))
}

pub fn verify_input<'a>(
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
    let spk = bitcoin::script::Script::from_bytes(job.prevout_script(input_index)?);
    let input = &tx.input[input_index];
    let has_witness = !input.witness.is_empty();

    if job.witness_active {
        if let Some((version, program)) = classify::witness_program(spk) {
            return verify_native_witness(job, input_index, tx, pre, tap_spent, version, program);
        }
    }

    let kind = classify::classify(spk);
    if job.witness_active && has_witness && !(matches!(kind, ScriptKind::P2sh) && job.bip16_active)
    {
        return Err(ConsensusError::Script("WITNESS_UNEXPECTED".into()));
    }

    match kind {
        ScriptKind::P2pkh => {
            if needs_interpreted_ecdsa(job) {
                return verify_bare(job, input_index, tx);
            }
            // Fast path: exact `<sig> <pubkey>` scriptSig. Historical mainnet has
            // non-standard P2PKH scriptSigs that still leave a valid stack for
            // scriptPubKey (e.g. height 218596: "p2pkh scriptSig len"). Fall back
            // only for scriptSig *shape* errors (not DER/ECDSA), so bip66 failure
            // codes stay.
            match p2pkh::verify(job, input_index, tx, sighash_cache(cache, tx)) {
                Ok(()) => Ok(()),
                Err(e) if p2pkh_scriptsig_shape_error(&e) => verify_bare(job, input_index, tx),
                Err(e) => Err(e),
            }
        }
        ScriptKind::P2sh => {
            // Pre-BIP16: HASH160/EQUAL is a bare script (push data, hash, equal) —
            // do **not** treat the last push as a redeemScript. Mainnet 170060.
            if !job.bip16_active {
                return verify_bare(job, input_index, tx);
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
            verify_bare(job, input_index, tx)
        }
    }
}

/// Core `IsPayToAnchor`: witness v1 program `0x4e73`.
#[doc(hidden)]
pub const PAY_TO_ANCHOR_PROGRAM: [u8; 2] = [0x4e, 0x73];

/// BIP141 native witness program (any version). `scriptSig` must be empty.
///
/// Policy: a v1 32-byte program before Taproot and pay-to-anchor succeed
/// without DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, as in Core.
#[inline]
#[doc(hidden)]
pub fn verify_native_witness(
    job: &ScriptCheckJob,
    input_index: usize,
    tx: &Transaction,
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
    if !bitcoin::script::read_scriptbool(program) {
        return Err(ConsensusError::Script("EVAL_FALSE".into()));
    }
    match (version, program.len()) {
        (0, 20) if needs_interpreted_ecdsa(job) => {
            p2wpkh::verify_interpreted(job, input_index, tx, program)
        }
        (0, 20) => p2wpkh::verify(job, input_index, tx, pre),
        (0, 32) => p2wsh::verify(job, input_index, tx),
        (0, _) => Err(ConsensusError::Script(
            "WITNESS_PROGRAM_WRONG_LENGTH".into(),
        )),
        (1, 32) if job.taproot_active => p2tr::verify(job, input_index, tx, tap_spent),
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

/// LOW_S / STRICTENC / NULLFAIL are interpreter policy. The typed P2PKH and
/// P2WPKH paths do not apply them, so those jobs use the interpreter.
#[doc(hidden)]
pub fn needs_interpreted_ecdsa(job: &ScriptCheckJob) -> bool {
    job.low_s || job.strictenc || job.nullfail
}

/// True when the P2PKH fast path failed because scriptSig is not exactly two
/// data pushes (still may be valid under the full interpreter).
#[doc(hidden)]
pub fn p2pkh_scriptsig_shape_error(err: &ConsensusError) -> bool {
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

#[doc(hidden)]
pub fn verify_bare(
    job: &ScriptCheckJob,
    input_index: usize,
    tx: &Transaction,
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
        )?;
        let _ = interpreter::eval_script(ss, &mut stack, &ctx_sig)?;
    }
    let spk = bitcoin::script::Script::from_bytes(job.prevout_script(input_index)?);
    let ctx = interpreter::EvalContext::from_job(
        job,
        tx,
        input_index,
        spk,
        interpreter::SigVersion::Base,
    )?;
    // Base `eval_script` returns `Ok(true)` or `Err`. `Ok(false)` is tapscript
    // OP_SUCCESS, which this sigversion does not produce, so the top check always runs.
    interpreter::eval_script(spk, &mut stack, &ctx)?;
    if job.cleanstack {
        interpreter::require_clean_true(&stack)?;
    } else {
        interpreter::require_true_top(&stack)?;
    }
    Ok(())
}

/// Shared ECDSA / secp helpers for typed paths.
#[doc(hidden)]
pub mod crypto {
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{ecdsa, Message, PublicKey, Secp256k1, VerifyOnly};

    use crate::error::ConsensusError;

    thread_local! {
        pub static SECP: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
    }

    /// Parse DER signature + **raw** sighash type byte (as `u32`).
    ///
    /// Important: do **not** run the type through `EcdsaSighashType::from_consensus`
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
        let (&sighash_byte, der) = sig_raw
            .split_last()
            .ok_or_else(|| ConsensusError::Script("der sig".into()))?;
        let sighash_ty = u32::from(sighash_byte);
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

    /// BIP119 default template hash (single SHA256, not tagged).
    ///
    /// Counts are `u32`, not compact size. `sha_sequences` and `sha_outputs`
    /// are already the single SHA256. When every scriptSig is empty the
    /// scriptSig hash is omitted, not hashed as empty scripts.
    pub fn ctv_default_hash(
        tx: &bitcoin::Transaction,
        pre: &crate::TxPrecompute,
        input_index: u32,
    ) -> Result<[u8; 32], ConsensusError> {
        use bitcoin::consensus::Encodable;
        use bitcoin::hashes::{sha256, Hash, HashEngine};

        let sequences = sighash_midstate(pre.sha_sequences)?;
        let outputs = sighash_midstate(pre.sha_outputs)?;
        let mut eng = sha256::Hash::engine();
        tx.version
            .consensus_encode(&mut eng)
            .expect("hash engines do not error");
        tx.lock_time
            .consensus_encode(&mut eng)
            .expect("hash engines do not error");
        if tx.input.iter().any(|inp| !inp.script_sig.is_empty()) {
            let mut scripts = sha256::Hash::engine();
            for inp in &tx.input {
                inp.script_sig
                    .consensus_encode(&mut scripts)
                    .expect("hash engines do not error");
            }
            eng.input(sha256::Hash::from_engine(scripts).as_byte_array());
        }
        eng.input(&(tx.input.len() as u32).to_le_bytes());
        eng.input(&sequences);
        eng.input(&(tx.output.len() as u32).to_le_bytes());
        eng.input(&outputs);
        eng.input(&input_index.to_le_bytes());
        Ok(sha256::Hash::from_engine(eng).to_byte_array())
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
    /// Fast path: when `raw_ty` round-trips through `EcdsaSighashType` (standard
    /// 0x01/02/03/81/82/83), use rust-bitcoin's `SighashCache` midstate
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
    /// taproot signature check that commits to the spent outputs.
    ///
    /// Hashes borrowed script bytes from the job. Does not build `TxOut`.
    #[derive(Default)]
    pub struct TapSpentHashes(std::cell::OnceCell<[[u8; 32]; 2]>);

    impl TapSpentHashes {
        #[doc(hidden)]
        pub fn get(
            &self,
            job: &crate::block::ScriptCheckJob,
        ) -> Result<[[u8; 32]; 2], ConsensusError> {
            if let Some(hashes) = self.0.get() {
                return Ok(*hashes);
            }
            let mut failed: Option<ConsensusError> = None;
            let mut spent = job.pre().clone();
            let n = job.prevouts.len();
            let ok = spent.finish_spent_parts(n, |i| match job.prevout_parts(i) {
                Ok((value, script)) => Some((value as i64, script)),
                Err(e) => {
                    failed = Some(e);
                    None
                }
            });
            if !ok {
                // `failed` is set whenever the callback returns `None`.
                return Err(
                    failed.unwrap_or(ConsensusError::Script("tapscript sighash prevouts".into()))
                );
            }
            let hashes = [
                sighash_midstate(spent.sha_amounts)?,
                sighash_midstate(spent.sha_scriptpubkeys)?,
            ];
            Ok(*self.0.get_or_init(|| hashes))
        }
    }

    /// SHA256 of `compact_size(annex) || annex` (BIP341, annex includes `0x50`).
    pub fn annex_hash(annex: &[u8]) -> [u8; 32] {
        use bitcoin::consensus::encode::VarInt;
        use bitcoin::consensus::Encodable;
        use bitcoin::hashes::{sha256, HashEngine};

        let mut eng = sha256::Hash::engine();
        VarInt(annex.len() as u64)
            .consensus_encode(&mut eng)
            .expect("hash engines do not error");
        eng.input(annex);
        sha256::Hash::from_engine(eng).to_byte_array()
    }

    /// BIP341 signature hash. `leaf` is `None` on the key path (ext flag 0)
    /// and `Some((tapleaf, codesep))` on the script path (ext flag 1).
    ///
    /// Prevout scripts are borrowed from `job`. This does not allocate `TxOut`.
    pub fn tap_signature_hash(
        job: &crate::block::ScriptCheckJob,
        input_index: usize,
        hash_type: bitcoin::sighash::TapSighashType,
        spent: &TapSpentHashes,
        annex_hash: Option<[u8; 32]>,
        leaf: Option<(bitcoin::TapLeafHash, u32)>,
        single_output_hash: &std::cell::OnceCell<Option<[u8; 32]>>,
    ) -> Result<[u8; 32], ConsensusError> {
        use bitcoin::consensus::Encodable;
        use bitcoin::hashes::{sha256, HashEngine};
        use bitcoin::sighash::TapSighash;

        const SIGHASH_ALL: u8 = 0x01;
        const SIGHASH_SINGLE: u8 = 0x03;
        const SIGHASH_ANYONECANPAY: u8 = 0x80;
        const KEY_VERSION: u8 = 0;

        let tx = &*job.tx;
        let Some(txin) = tx.input.get(input_index) else {
            return Err(ConsensusError::Script("tapscript sighash input".into()));
        };
        if job.prevouts.len() != tx.input.len() {
            return Err(ConsensusError::Script("tapscript sighash prevouts".into()));
        }
        let pre = job.pre();
        let hash_type = hash_type as u8;
        let output_type = match hash_type {
            0 => SIGHASH_ALL,
            ty => ty & 0x03,
        };
        let anyone_can_pay = hash_type & SIGHASH_ANYONECANPAY != 0;
        let ext_flag = u8::from(leaf.is_some());

        let mut eng = TapSighash::engine();
        eng.input(&[0, hash_type]);
        tx.version
            .consensus_encode(&mut eng)
            .expect("hash engines do not error");
        tx.lock_time
            .consensus_encode(&mut eng)
            .expect("hash engines do not error");
        if !anyone_can_pay {
            let [sha_amounts, sha_scriptpubkeys] = spent.get(job)?;
            eng.input(&sighash_midstate(pre.sha_prevouts)?);
            eng.input(&sha_amounts);
            eng.input(&sha_scriptpubkeys);
            eng.input(&sighash_midstate(pre.sha_sequences)?);
        }
        if output_type == SIGHASH_ALL {
            eng.input(&sighash_midstate(pre.sha_outputs)?);
        }
        eng.input(&[(ext_flag << 1) | u8::from(annex_hash.is_some())]);
        if anyone_can_pay {
            let (value, script) = job.prevout_parts(input_index)?;
            txin.previous_output
                .consensus_encode(&mut eng)
                .expect("hash engines do not error");
            value
                .consensus_encode(&mut eng)
                .expect("hash engines do not error");
            bitcoin::Script::from_bytes(script)
                .consensus_encode(&mut eng)
                .expect("hash engines do not error");
            txin.sequence
                .consensus_encode(&mut eng)
                .expect("hash engines do not error");
        } else {
            eng.input(&(input_index as u32).to_le_bytes());
        }
        if let Some(annex_hash) = &annex_hash {
            eng.input(annex_hash);
        }
        if output_type == SIGHASH_SINGLE {
            let output_hash = single_output_hash.get_or_init(|| {
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
        if let Some((tapleaf_hash, codeseparator_pos)) = leaf {
            eng.input(tapleaf_hash.as_byte_array());
            eng.input(&[KEY_VERSION]);
            eng.input(&codeseparator_pos.to_le_bytes());
        }
        Ok(TapSighash::from_engine(eng).to_byte_array())
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
        job: &'a crate::block::ScriptCheckJob,
        input_index: usize,
        spent: &'a TapSpentHashes,
        tapleaf_hash: bitcoin::TapLeafHash,
        annex_hash: Option<[u8; 32]>,
        single_output_hash: std::cell::OnceCell<Option<[u8; 32]>>,
    }

    impl<'a> TapscriptExecData<'a> {
        /// `annex` is the BIP341 annex including its `0x50` tag. `spent`
        /// belongs to `job`'s transaction.
        pub fn new(
            job: &'a crate::block::ScriptCheckJob,
            input_index: usize,
            spent: &'a TapSpentHashes,
            tapleaf_hash: bitcoin::TapLeafHash,
            annex: Option<&[u8]>,
        ) -> Self {
            Self {
                job,
                input_index,
                spent,
                tapleaf_hash,
                annex_hash: annex.map(annex_hash),
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
            tap_signature_hash(
                self.job,
                self.input_index,
                hash_type,
                self.spent,
                self.annex_hash,
                Some((self.tapleaf_hash, codeseparator_pos)),
                &self.single_output_hash,
            )
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
}
