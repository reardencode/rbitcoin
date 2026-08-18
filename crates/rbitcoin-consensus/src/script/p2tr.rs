//! Taproot (P2TR) verification: BIP341 key-path and script-path.
//!
//! Script-path fully re-checks the BIP341 output-key commitment via
//! [`bitcoin::taproot::ControlBlock::verify_taproot_commitment`] (merkle path +
//! `TapTweak` + `tweak_add_check` against the prevout x-only key).

use bitcoin::hashes::Hash;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::{Annex, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::ControlBlock;
use bitcoin::{Transaction, Witness};

use super::crypto;
use super::interpreter::{self, EvalContext, SigVersion};
use crate::block::ScriptCheckJob;
use crate::error::ConsensusError;

pub(crate) fn verify(
    job: &ScriptCheckJob,
    input_index: usize,
    tx: &Transaction,
    cache: &mut SighashCache<&Transaction>,
) -> Result<(), ConsensusError> {
    let spk = job.prevouts[input_index].script_pubkey.as_bytes();
    debug_assert!(spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20);
    let output_key = &spk[2..34];

    let input = &tx.input[input_index];
    let wit_len = input.witness.len();
    if wit_len == 0 {
        return Err(ConsensusError::Script("p2tr empty witness".into()));
    }

    // Key-path: one element, or sig + annex (BIP341: annex = last stack item
    // starting with 0x50 when there are ≥2 items).
    if wit_len == 1 || (wit_len == 2 && bip341_annex(&input.witness).is_some()) {
        return verify_key_path(job, input_index, tx, output_key, cache);
    }
    verify_script_path(job, input_index, tx, output_key)
}

/// BIP341 annex: last witness item, only when `len ≥ 2` and first byte is `0x50`.
///
/// Shared with tapscript CHECKSIG sighash (must include annex when present).
pub(crate) fn bip341_annex(witness: &Witness) -> Option<&[u8]> {
    if witness.len() < 2 {
        return None;
    }
    let last = witness.last()?;
    if !last.is_empty() && last[0] == 0x50 {
        Some(last)
    } else {
        None
    }
}

fn verify_key_path(
    job: &ScriptCheckJob,
    input_index: usize,
    tx: &Transaction,
    output_key: &[u8],
    cache: &mut SighashCache<&Transaction>,
) -> Result<(), ConsensusError> {
    let input = &tx.input[input_index];
    let sig_raw = input
        .witness
        .nth(0)
        .ok_or_else(|| ConsensusError::Script("p2tr sig".into()))?;

    let (sig_bytes, sighash_ty) = if sig_raw.len() == 64 {
        (sig_raw, TapSighashType::Default)
    } else if sig_raw.len() == 65 {
        // BIP341: 65-byte form with sighash byte 0x00 is invalid (Core /
        // EvalChecksigTapscript). Mirror tapscript `checksig_schnorr`.
        if sig_raw[64] == 0x00 {
            return Err(ConsensusError::Script("p2tr sighash type".into()));
        }
        let ty = TapSighashType::from_consensus_u8(sig_raw[64])
            .map_err(|_| ConsensusError::Script("p2tr sighash type".into()))?;
        (&sig_raw[..64], ty)
    } else {
        return Err(ConsensusError::Script("p2tr sig len".into()));
    };

    let xonly = XOnlyPublicKey::from_slice(output_key)
        .map_err(|_| ConsensusError::Script("p2tr xonly".into()))?;
    let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(sig_bytes)
        .map_err(|_| ConsensusError::Script("p2tr schnorr parse".into()))?;

    let prevouts = Prevouts::All(&job.prevouts);
    // BIP341: when the annex is present it is part of spend_type / sighash.
    // `taproot_key_spend_signature_hash` always passes annex=None — wrong for
    // annex spends (mainnet 896078 / f859a4e6… style).
    let annex = bip341_annex(&input.witness)
        .map(Annex::new)
        .transpose()
        .map_err(|_| ConsensusError::Script("p2tr annex".into()))?;
    let sighash = cache
        .taproot_signature_hash(input_index, &prevouts, annex, None, sighash_ty)
        .map_err(|_| ConsensusError::Script("p2tr sighash".into()))?;
    let msg = Message::from_digest(sighash.to_byte_array());
    crypto::SECP.with(|secp| {
        secp.verify_schnorr(&sig, &msg, &xonly)
            .map_err(|_| ConsensusError::Script("p2tr schnorr".into()))
    })
}

fn verify_script_path(
    job: &ScriptCheckJob,
    input_index: usize,
    tx: &Transaction,
    output_key_bytes: &[u8],
) -> Result<(), ConsensusError> {
    let input = &tx.input[input_index];
    let mut items: Vec<Vec<u8>> = (0..input.witness.len())
        .filter_map(|i| input.witness.nth(i).map(|b| b.to_vec()))
        .collect();

    // Strip annex from the initial stack (still included in CHECKSIG sighash).
    if bip341_annex(&input.witness).is_some() {
        items.pop();
    }
    if items.len() < 2 {
        return Err(ConsensusError::Script("p2tr script path short".into()));
    }
    let control_bytes = items.pop().unwrap();
    let script_bytes = items.pop().unwrap();
    let mut stack = items;

    let control = ControlBlock::decode(&control_bytes)
        .map_err(|e| ConsensusError::Script(format!("p2tr control block: {e}")))?;

    let output_key = XOnlyPublicKey::from_slice(output_key_bytes)
        .map_err(|_| ConsensusError::Script("p2tr output key".into()))?;
    let script = bitcoin::script::Script::from_bytes(&script_bytes);

    // BIP341: recompute merkle root from leaf + path, apply TapTweak to internal
    // key, and check it matches the prevout output key (with claimed parity).
    let ok = crypto::SECP.with(|secp| control.verify_taproot_commitment(secp, output_key, script));
    if !ok {
        return Err(ConsensusError::Script("p2tr bip341 tweak mismatch".into()));
    }

    // BIP341: only tapscript (0xc0) is executed. Any other leaf version is
    // reserved for future soft forks and **succeeds** after the commitment
    // check (above). Core rejects unknown leaves only under mempool
    // SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION — never on blocks.
    if control.leaf_version != bitcoin::taproot::LeafVersion::TapScript {
        return Ok(());
    }

    let ctx = EvalContext::from_job(job, tx, input_index, script, SigVersion::TapScript);
    if interpreter::eval_script(script, &mut stack, &ctx)? {
        interpreter::require_clean_true(&stack)?;
    }
    Ok(())
}

#[cfg(test)]
mod bip341_tests {
    use super::*;
    use crate::script;
    use bitcoin::absolute::LockTime;
    use bitcoin::key::{TapTweak, TweakedKeypair};
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use bitcoin::taproot::{LeafVersion, TaprootBuilder};
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

    fn p2tr_spk(output_key: XOnlyPublicKey) -> ScriptBuf {
        let mut b = vec![0x51, 0x20];
        b.extend_from_slice(&output_key.serialize());
        ScriptBuf::from_bytes(b)
    }

    /// Single-leaf tree: leaf script `OP_TRUE`, empty initial stack.
    fn make_script_path_spend() -> (ScriptCheckJob, ControlBlock) {
        let secp = Secp256k1::new();
        let internal_sk = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let internal_kp = Keypair::from_secret_key(&secp, &internal_sk);
        let (internal_xonly, _) = internal_kp.x_only_public_key();

        let leaf = ScriptBuf::from_bytes(vec![0x51]); // OP_TRUE
        let builder = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("leaf");
        let spend_info = builder.finalize(&secp, internal_xonly).expect("finalize");
        let output_key = spend_info.output_key().to_x_only_public_key();
        let control = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control");

        // Sanity: rust-bitcoin's own check must pass for our fixture.
        assert!(control.verify_taproot_commitment(&secp, output_key, leaf.as_script()));

        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2tr_spk(output_key),
        };
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::from_slice(&[leaf.as_bytes(), control.serialize().as_slice()]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let job = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![prevout],
            tx: crate::block::JobTx::owned(tx.clone()),
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
            pre: std::sync::OnceLock::new(),
        };
        (job, control)
    }

    #[test]
    fn script_path_accepts_with_valid_bip341_tweak() {
        let (job, _) = make_script_path_spend();
        script::verify_job_all_inputs(&job).expect("p2tr script path");
    }

    /// BIP341: after commitment verify, a non-tapscript leaf version succeeds
    /// without executing the leaf (upgrade path). Block validation must not
    /// reject this — Core only discourages it as mempool policy.
    #[test]
    fn script_path_accepts_unknown_taproot_leaf_version() {
        let secp = Secp256k1::new();
        let internal_sk = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let internal_kp = Keypair::from_secret_key(&secp, &internal_sk);
        let (internal_xonly, _) = internal_kp.x_only_public_key();

        let leaf = ScriptBuf::from_bytes(vec![0x51]);
        let ver = LeafVersion::from_consensus(0xc2).expect("0xc2 is a valid leaf version");
        let builder = TaprootBuilder::new()
            .add_leaf_with_ver(0, leaf.clone(), ver)
            .expect("leaf");
        let spend_info = builder.finalize(&secp, internal_xonly).expect("finalize");
        let output_key = spend_info.output_key().to_x_only_public_key();
        let control = spend_info
            .control_block(&(leaf.clone(), ver))
            .expect("control");
        assert!(control.verify_taproot_commitment(&secp, output_key, leaf.as_script()));
        assert_ne!(control.leaf_version, LeafVersion::TapScript);

        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2tr_spk(output_key),
        };
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::from_slice(&[leaf.as_bytes(), control.serialize().as_slice()]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let job = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![prevout],
            tx: crate::block::JobTx::owned(tx),
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
            pre: std::sync::OnceLock::new(),
        };
        script::verify_job_all_inputs(&job)
            .expect("unknown tapleaf must succeed after BIP341 commitment");
    }

    #[test]
    fn script_path_rejects_wrong_output_key() {
        let (mut job, _) = make_script_path_spend();
        // Flip a byte in the prevout output key → BIP341 commitment fails.
        let spk = job.prevouts[0].script_pubkey.as_bytes();
        let mut bad = spk.to_vec();
        bad[10] ^= 0x01;
        job.prevouts[0].script_pubkey = ScriptBuf::from_bytes(bad);
        let err = script::verify_job_all_inputs(&job).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("bip341") || msg.contains("tweak") || msg.contains("script"),
            "unexpected err: {msg}"
        );
    }

    #[test]
    fn script_path_rejects_tampered_control_block() {
        let (mut job, _) = make_script_path_spend();
        let leaf = job.tx.input[0].witness.nth(0).unwrap().to_vec();
        let mut ctrl = job.tx.input[0].witness.nth(1).unwrap().to_vec();
        // Corrupt internal key inside control block (bytes 1..33).
        ctrl[5] ^= 0xff;
        job.tx.input[0].witness = Witness::from_slice(&[leaf.as_slice(), ctrl.as_slice()]);
        assert!(script::verify_job_all_inputs(&job).is_err());
    }

    #[test]
    fn empty_witness_and_bad_sig_len() {
        let mut spk = vec![0x51, 0x20];
        spk.extend([0u8; 32]);
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
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            }),
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
            pre: std::sync::OnceLock::new(),
        };
        let mut cache = SighashCache::new(&*job.tx);
        assert!(verify(&job, 0, &*job.tx, &mut cache).is_err());

        let mut job2 = job;
        job2.tx.input[0].witness = Witness::from_slice(&[vec![0u8; 10]]);
        let mut cache2 = SighashCache::new(&*job2.tx);
        assert!(verify(&job2, 0, &*job2.tx, &mut cache2).is_err());
    }

    #[test]
    fn key_path_accepts_valid_schnorr() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[4u8; 32]).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (internal, _) = kp.x_only_public_key();
        // Key-path only (no script tree): merkle_root = None
        let tweaked: TweakedKeypair = kp.tap_tweak(&secp, None);
        let output_key = tweaked.to_keypair().x_only_public_key().0;

        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2tr_spk(output_key),
        };
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };

        let mut cache = SighashCache::new(&tx);
        let prevouts = Prevouts::All(std::slice::from_ref(&prevout));
        let sighash = cache
            .taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::Default)
            .unwrap();
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_keypair());
        tx.input[0].witness = Witness::from_slice(&[sig.as_ref()]);

        let _ = internal; // used implicitly via tweak
        let job = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![prevout],
            tx: crate::block::JobTx::owned(tx.clone()),
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
            pre: std::sync::OnceLock::new(),
        };
        script::verify_job_all_inputs(&job).expect("p2tr key path");
    }

    /// Finding 008: 65-byte key-path sig with sighash byte 0x00 is invalid (BIP341).
    #[test]
    fn key_path_rejects_65_byte_sighash_byte_zero() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[4u8; 32]).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let tweaked: TweakedKeypair = kp.tap_tweak(&secp, None);
        let output_key = tweaked.to_keypair().x_only_public_key().0;

        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2tr_spk(output_key),
        };
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };

        let mut cache = SighashCache::new(&tx);
        let prevouts = Prevouts::All(std::slice::from_ref(&prevout));
        let sighash = cache
            .taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::Default)
            .unwrap();
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_keypair());
        // Valid 64-byte form, then append illegal 0x00 sighash byte.
        let mut sig65 = sig.as_ref().to_vec();
        sig65.push(0x00);
        tx.input[0].witness = Witness::from_slice(&[sig65.as_slice()]);

        let job = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![prevout],
            tx: crate::block::JobTx::owned(tx.clone()),
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
            pre: std::sync::OnceLock::new(),
        };
        let err = script::verify_job_all_inputs(&job).expect_err("0x00 sighash must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("sighash") || msg.contains("p2tr"),
            "expected key-path sighash reject, got {err}"
        );

        // Control: plain 64-byte still accepted (same key material as above).
        let mut tx64 = (*job.tx).clone();
        tx64.input[0].witness = Witness::from_slice(&[sig.as_ref()]);
        let job64 = ScriptCheckJob {
            tx: crate::block::JobTx::owned(tx64),
            prevouts: job.prevouts.clone(),
            ..job
        };
        script::verify_job_all_inputs(&job64).expect("64-byte Default key-path control");
    }

    /// BIP341: annex (last item starting with 0x50) is part of the key-path sighash.
    /// Signing without annex while spending with annex must fail; with annex, pass.
    #[test]
    fn key_path_annex_must_enter_sighash() {
        use bitcoin::sighash::Annex;

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let tweaked: TweakedKeypair = kp.tap_tweak(&secp, None);
        let output_key = tweaked.to_keypair().x_only_public_key().0;
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2tr_spk(output_key),
        };
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let annex_bytes: &[u8] = &[0x50, 0x00, 0xde, 0xad]; // Libre-legal payload
        let prevouts = Prevouts::All(std::slice::from_ref(&prevout));

        // Sign WITHOUT annex, spend WITH annex → must fail (historical bug).
        {
            let mut cache = SighashCache::new(&tx);
            let sh = cache
                .taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::Default)
                .unwrap();
            let sig = secp.sign_schnorr_no_aux_rand(
                &Message::from_digest(sh.to_byte_array()),
                &tweaked.to_keypair(),
            );
            let sig_v = sig.as_ref().to_vec();
            let annex_v = annex_bytes.to_vec();
            tx.input[0].witness = Witness::from_slice(&[sig_v.as_slice(), annex_v.as_slice()]);
            let job = ScriptCheckJob {
                txid: [0u8; 32],
                prevouts: vec![prevout.clone()],
                tx: crate::block::JobTx::owned(tx.clone()),
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
                pre: std::sync::OnceLock::new(),
            };
            let err = script::verify_job_all_inputs(&job).unwrap_err();
            assert!(
                format!("{err}").contains("schnorr") || format!("{err}").contains("script"),
                "missing annex in sighash should fail: {err}"
            );
        }

        // Sign WITH annex → must pass.
        {
            let annex = Annex::new(annex_bytes).unwrap();
            let mut cache = SighashCache::new(&tx);
            let sh = cache
                .taproot_signature_hash(0, &prevouts, Some(annex), None, TapSighashType::Default)
                .unwrap();
            let sig = secp.sign_schnorr_no_aux_rand(
                &Message::from_digest(sh.to_byte_array()),
                &tweaked.to_keypair(),
            );
            let sig_v = sig.as_ref().to_vec();
            let annex_v = annex_bytes.to_vec();
            tx.input[0].witness = Witness::from_slice(&[sig_v.as_slice(), annex_v.as_slice()]);
            let job = ScriptCheckJob {
                txid: [0u8; 32],
                prevouts: vec![prevout],
                tx: crate::block::JobTx::owned(tx.clone()),
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
                pre: std::sync::OnceLock::new(),
            };
            script::verify_job_all_inputs(&job).expect("key path + annex");
        }
    }

    /// Empty annex tag only (`[0x50]`) is still an annex for BIP341.
    #[test]
    fn key_path_empty_annex_payload() {
        use bitcoin::sighash::Annex;

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[8u8; 32]).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let tweaked: TweakedKeypair = kp.tap_tweak(&secp, None);
        let output_key = tweaked.to_keypair().x_only_public_key().0;
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2tr_spk(output_key),
        };
        let annex_bytes: &[u8] = &[0x50];
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let prevouts = Prevouts::All(std::slice::from_ref(&prevout));
        let annex = Annex::new(annex_bytes).unwrap();
        let mut cache = SighashCache::new(&tx);
        let sh = cache
            .taproot_signature_hash(0, &prevouts, Some(annex), None, TapSighashType::Default)
            .unwrap();
        // Annex-less sighash differs.
        let sh_no = cache
            .taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::Default)
            .unwrap();
        assert_ne!(sh, sh_no);
        let sig = secp.sign_schnorr_no_aux_rand(
            &Message::from_digest(sh.to_byte_array()),
            &tweaked.to_keypair(),
        );
        let sig_v = sig.as_ref().to_vec();
        let annex_v = annex_bytes.to_vec();
        tx.input[0].witness = Witness::from_slice(&[sig_v.as_slice(), annex_v.as_slice()]);
        let job = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![prevout],
            tx: crate::block::JobTx::owned(tx),
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
            pre: std::sync::OnceLock::new(),
        };
        script::verify_job_all_inputs(&job).expect("empty annex payload");
    }

    /// Script-path stack with annex: CHECKSIG must bind annex in sighash.
    #[test]
    fn script_path_annex_checksig() {
        use bitcoin::sighash::Annex;
        use bitcoin::taproot::LeafVersion;
        use bitcoin::TapLeafHash;

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[9u8; 32]).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();
        // leaf: <xonly> CHECKSIG
        let mut leaf_bytes = vec![0x20];
        leaf_bytes.extend_from_slice(&xonly.serialize());
        leaf_bytes.push(0xac);
        let leaf = ScriptBuf::from_bytes(leaf_bytes);

        let internal_sk = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let internal_kp = Keypair::from_secret_key(&secp, &internal_sk);
        let (internal_xonly, _) = internal_kp.x_only_public_key();
        let builder = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("leaf");
        let spend_info = builder.finalize(&secp, internal_xonly).expect("finalize");
        let output_key = spend_info.output_key().to_x_only_public_key();
        let control = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control");

        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2tr_spk(output_key),
        };
        let annex_bytes: &[u8] = &[0x50, 0x00];
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let leaf_hash = TapLeafHash::from_script(leaf.as_script(), LeafVersion::TapScript);
        let prevouts = Prevouts::All(std::slice::from_ref(&prevout));
        let annex = Annex::new(annex_bytes).unwrap();
        let mut cache = SighashCache::new(&tx);
        let sh = cache
            .taproot_signature_hash(
                0,
                &prevouts,
                Some(annex),
                Some((leaf_hash, 0xFFFF_FFFF)),
                TapSighashType::Default,
            )
            .unwrap();
        let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sh.to_byte_array()), &kp);
        let ctrl = control.serialize();
        let sig_v = sig.as_ref().to_vec();
        let leaf_v = leaf.as_bytes().to_vec();
        let annex_v = annex_bytes.to_vec();
        tx.input[0].witness = Witness::from_slice(&[
            sig_v.as_slice(),
            leaf_v.as_slice(),
            ctrl.as_slice(),
            annex_v.as_slice(),
        ]);
        let job = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![prevout],
            tx: crate::block::JobTx::owned(tx),
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
            pre: std::sync::OnceLock::new(),
        };
        script::verify_job_all_inputs(&job).expect("script path + annex CHECKSIG");
    }

    #[test]
    fn bip341_annex_detection_edges() {
        // <2 items: never annex
        let w1 = Witness::from_slice(&[vec![0x50]]);
        assert!(bip341_annex(&w1).is_none());
        assert!(bip341_annex(&Witness::new()).is_none());
        // 2 items, last not 0x50
        let w2 = Witness::from_slice(&[vec![1], vec![0xc0, 1, 2]]);
        assert!(bip341_annex(&w2).is_none());
        // 2 items, last is annex
        let w3 = Witness::from_slice(&[vec![1], vec![0x50]]);
        assert_eq!(bip341_annex(&w3), Some(&[0x50][..]));
        // empty last (no 0x50)
        let w4 = Witness::from_slice(&[vec![1], vec![]]);
        assert!(bip341_annex(&w4).is_none());
    }

    /// Two-leaf tree: spend the right leaf so the control block carries a
    /// non-empty merkle path (exercises branch folding in BIP341).
    #[test]
    fn script_path_two_leaf_merkle_path() {
        let secp = Secp256k1::new();
        let internal_sk = SecretKey::from_slice(&[6u8; 32]).unwrap();
        let internal_kp = Keypair::from_secret_key(&secp, &internal_sk);
        let (internal_xonly, _) = internal_kp.x_only_public_key();

        // DFS order: left then right at depth 1.
        let left = ScriptBuf::from_bytes(vec![0x51, 0x51]); // OP_TRUE OP_TRUE (not used)
        let right = ScriptBuf::from_bytes(vec![0x51]); // OP_TRUE
        let builder = TaprootBuilder::new()
            .add_leaf(1, left)
            .unwrap()
            .add_leaf(1, right.clone())
            .unwrap();
        let spend_info = builder.finalize(&secp, internal_xonly).unwrap();
        let output_key = spend_info.output_key().to_x_only_public_key();
        let control = spend_info
            .control_block(&(right.clone(), LeafVersion::TapScript))
            .expect("control for right leaf");
        assert!(!control.merkle_branch.is_empty(), "expect sibling in path");
        assert!(control.verify_taproot_commitment(&secp, output_key, right.as_script()));

        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2tr_spk(output_key),
        };
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::from_slice(&[right.as_bytes(), control.serialize().as_slice()]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let job = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![prevout],
            tx: crate::block::JobTx::owned(tx.clone()),
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
            pre: std::sync::OnceLock::new(),
        };
        script::verify_job_all_inputs(&job).expect("two-leaf script path");
    }

    /// Sequential CHECKSIGVERIFY + CODESEPARATOR + CHECKSIG (signet 90719 shape).
    /// Each CHECKSIG* must bind a different codeseparator_pos in the BIP341 sighash.
    #[test]
    fn script_path_codeseparator_checksig_chain() {
        use bitcoin::secp256k1::Message;
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
        use bitcoin::taproot::LeafVersion;
        use bitcoin::TapLeafHash;

        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_slice(&[11u8; 32]).unwrap();
        let sk2 = SecretKey::from_slice(&[12u8; 32]).unwrap();
        let kp1 = Keypair::from_secret_key(&secp, &sk1);
        let kp2 = Keypair::from_secret_key(&secp, &sk2);
        let (x1, _) = kp1.x_only_public_key();
        let (x2, _) = kp2.x_only_public_key();

        // leaf: <x1> CHECKSIGVERIFY CODESEPARATOR <x2> CHECKSIG
        let mut leaf_bytes = Vec::new();
        leaf_bytes.push(0x20);
        leaf_bytes.extend_from_slice(&x1.serialize());
        leaf_bytes.push(0xad); // CHECKSIGVERIFY
        leaf_bytes.push(0xab); // CODESEPARATOR  (instruction index 2)
        leaf_bytes.push(0x20);
        leaf_bytes.extend_from_slice(&x2.serialize());
        leaf_bytes.push(0xac); // CHECKSIG
        let leaf = ScriptBuf::from_bytes(leaf_bytes);

        let internal_sk = SecretKey::from_slice(&[13u8; 32]).unwrap();
        let internal_kp = Keypair::from_secret_key(&secp, &internal_sk);
        let (internal_xonly, _) = internal_kp.x_only_public_key();
        let builder = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("leaf");
        let spend_info = builder.finalize(&secp, internal_xonly).expect("finalize");
        let output_key = spend_info.output_key().to_x_only_public_key();
        let control = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control");

        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2tr_spk(output_key),
        };
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };

        let leaf_hash = TapLeafHash::from_script(leaf.as_script(), LeafVersion::TapScript);
        let prevouts = Prevouts::All(std::slice::from_ref(&prevout));
        let mut cache = SighashCache::new(&tx);
        // First CHECKSIGVERIFY: no CODESEPARATOR yet → 0xFFFFFFFF
        let sh1 = cache
            .taproot_signature_hash(
                0,
                &prevouts,
                None,
                Some((leaf_hash, 0xFFFF_FFFF)),
                TapSighashType::Default,
            )
            .unwrap();
        // Second CHECKSIG: after CODESEPARATOR at instruction index 2
        let sh2 = cache
            .taproot_signature_hash(
                0,
                &prevouts,
                None,
                Some((leaf_hash, 2)),
                TapSighashType::Default,
            )
            .unwrap();
        assert_ne!(sh1, sh2, "codesep must change sighash");
        let sig1 = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sh1.to_byte_array()), &kp1);
        let sig2 = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sh2.to_byte_array()), &kp2);

        // Initial stack is witness order; top is last. CHECKSIGVERIFY consumes the
        // top sig first (against x1), then CHECKSIG uses the remaining (against x2).
        let ctrl = control.serialize();
        let wit_items: [&[u8]; 4] = [
            sig2.as_ref(),
            sig1.as_ref(),
            leaf.as_bytes(),
            ctrl.as_slice(),
        ];
        tx.input[0].witness = Witness::from_slice(&wit_items);
        let job = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![prevout],
            tx: crate::block::JobTx::owned(tx.clone()),
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
            pre: std::sync::OnceLock::new(),
        };
        script::verify_job_all_inputs(&job).expect("CODESEPARATOR chain must verify");
    }

    #[test]
    fn key_path_rejects_bad_sig() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[5u8; 32]).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let tweaked: TweakedKeypair = kp.tap_tweak(&secp, None);
        let output_key = tweaked.to_keypair().x_only_public_key().0;

        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2tr_spk(output_key),
        };
        // 64 zero bytes is not a valid Schnorr sig for this key.
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[[0u8; 64].as_slice()]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let job = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![prevout],
            tx: crate::block::JobTx::owned(tx.clone()),
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
            pre: std::sync::OnceLock::new(),
        };
        assert!(script::verify_job_all_inputs(&job).is_err());
    }
}
