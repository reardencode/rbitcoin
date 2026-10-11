//! Taproot (P2TR) verification: BIP341 key-path and script-path.
//!
//! Script-path fully re-checks the BIP341 output-key commitment (merkle path +
//! `TapTweak` + tweak check against the prevout x-only key). Signature and
//! tweak checks go through [`super::batch`], which defers them in block
//! confirm.

use bitcoin::consensus::Encodable;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::script::Script;
use bitcoin::sighash::TapSighashType;
use bitcoin::taproot::{TapLeafHash, TapNodeHash, TapTweakHash};
use bitcoin::{Transaction, Witness};

use super::batch;
use super::crypto;
use super::interpreter::{self, EvalContext, SigVersion};
use crate::block::ScriptCheckJob;
use crate::error::ConsensusError;

pub(crate) fn verify(
    job: &ScriptCheckJob,
    input_index: usize,
    tx: &Transaction,
    tap_spent: &crypto::TapSpentHashes,
) -> Result<(), ConsensusError> {
    let spk = job.prevout_script(input_index)?;
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
        return verify_key_path(job, input_index, tx, output_key, tap_spent);
    }
    verify_script_path(job, input_index, tx, output_key, tap_spent)
}

/// BIP341 annex: last witness item, only when `len ≥ 2` and first byte is `0x50`.
fn bip341_annex(witness: &Witness) -> Option<&[u8]> {
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
    tap_spent: &crypto::TapSpentHashes,
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

    // BIP341: when the annex is present it is part of spend_type / sighash.
    // Key path is the same message as script path with ext flag 0 (`leaf` absent).
    let annex_hash = bip341_annex(&input.witness).map(crypto::annex_hash);
    let single = std::cell::OnceCell::new();
    let sighash = crypto::tap_signature_hash(
        job,
        input_index,
        sighash_ty,
        tap_spent,
        annex_hash,
        None,
        &single,
    )?;
    let sig: &[u8; 64] = sig_bytes.try_into().expect("64-byte signature");
    let output_key: &[u8; 32] = output_key.try_into().expect("32-byte program");
    if !batch::verify_schnorr(sig, &sighash, output_key) {
        return Err(ConsensusError::Script("p2tr schnorr".into()));
    }
    Ok(())
}

const TAPSCRIPT_LEAF: u8 = 0xc0;
const CONTROL_BASE: usize = 33;
const CONTROL_NODE: usize = 32;
const CONTROL_MAX_NODES: usize = 128;

/// BIP341 commitment. Returns the even leaf version byte and the tapleaf hash.
fn verify_control_commitment(
    control: &[u8],
    output_key_bytes: &[u8],
    script: &Script,
) -> Result<(u8, TapLeafHash), ConsensusError> {
    if control.len() < CONTROL_BASE {
        return Err(ConsensusError::Script("TAPROOT_WRONG_CONTROL_SIZE".into()));
    }
    let extra = control.len() - CONTROL_BASE;
    let nodes = extra / CONTROL_NODE;
    if !extra.is_multiple_of(CONTROL_NODE) || nodes > CONTROL_MAX_NODES {
        return Err(ConsensusError::Script("TAPROOT_WRONG_CONTROL_SIZE".into()));
    }
    let leaf = control[0] & 0xfe;
    let odd = control[0] & 1 == 1;
    let internal: &[u8; 32] = control[1..CONTROL_BASE]
        .try_into()
        .expect("32-byte internal key");
    let output_key: &[u8; 32] = output_key_bytes.try_into().expect("32-byte program");

    let mut eng = TapLeafHash::engine();
    leaf.consensus_encode(&mut eng)
        .expect("hash engines do not error");
    script
        .consensus_encode(&mut eng)
        .expect("hash engines do not error");
    let tapleaf_hash = TapLeafHash::from_engine(eng);
    let mut curr = TapNodeHash::from_byte_array(tapleaf_hash.to_byte_array());
    for i in 0..nodes {
        let start = CONTROL_BASE + i * CONTROL_NODE;
        let node = TapNodeHash::from_byte_array(
            control[start..start + CONTROL_NODE]
                .try_into()
                .expect("32-byte merkle node"),
        );
        curr = TapNodeHash::from_node_hashes(curr, node);
    }
    // `TapTweakHash::from_key_and_tweak` over the raw key bytes.
    let mut eng = TapTweakHash::engine();
    eng.input(internal);
    eng.input(curr.as_ref());
    let tweak = TapTweakHash::from_engine(eng).to_byte_array();
    if !batch::tweak_add_check(output_key, odd, internal, &tweak) {
        return Err(ConsensusError::Script("WITNESS_PROGRAM_MISMATCH".into()));
    }
    Ok((leaf, tapleaf_hash))
}

fn verify_script_path(
    job: &ScriptCheckJob,
    input_index: usize,
    tx: &Transaction,
    output_key_bytes: &[u8],
    tap_spent: &crypto::TapSpentHashes,
) -> Result<(), ConsensusError> {
    let input = &tx.input[input_index];
    let mut items: Vec<Vec<u8>> = (0..input.witness.len())
        .filter_map(|i| input.witness.nth(i).map(|b| b.to_vec()))
        .collect();

    // Strip annex from the initial stack (still included in CHECKSIG sighash).
    let annex = bip341_annex(&input.witness);
    if annex.is_some() {
        items.pop();
    }
    if items.len() < 2 {
        return Err(ConsensusError::Script("p2tr script path short".into()));
    }
    let control_bytes = items.pop().unwrap();
    let script_bytes = items.pop().unwrap();
    let mut stack = items;

    let script = Script::from_bytes(&script_bytes);
    // Leaf byte is raw consensus (`c[0] & 0xfe`). `LeafVersion::from_consensus`
    // rejects 0x50, which Core accepts as a future leaf.
    let (leaf, tapleaf_hash) = verify_control_commitment(&control_bytes, output_key_bytes, script)?;

    if leaf != TAPSCRIPT_LEAF {
        if job.flags.discourage_upgradable_witness {
            return Err(ConsensusError::Script(
                "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION".into(),
            ));
        }
        return Ok(());
    }

    let exec = crypto::TapscriptExecData::new(job, input_index, tap_spent, tapleaf_hash, annex);
    let ctx = EvalContext::from_job(job, tx, input_index, script, SigVersion::TapScript)?
        .with_tapscript(exec);
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
    use bitcoin::key::{TapTweak, TweakedKeypair, XOnlyPublicKey};
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootBuilder};
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

    fn owned_prevout_mut(job: &mut ScriptCheckJob) -> &mut TxOut {
        let crate::block::JobPrevouts::Owned(v) = &mut job.prevouts else {
            panic!("owned prevouts");
        };
        &mut v[0]
    }

    fn p2tr_spk(output_key: XOnlyPublicKey) -> ScriptBuf {
        let mut b = vec![0x51, 0x20];
        b.extend_from_slice(&output_key.serialize());
        ScriptBuf::from_bytes(b)
    }

    /// Single-leaf tree: leaf script `OP_TRUE`, empty initial stack.
    fn make_script_path_spend() -> (ScriptCheckJob, ControlBlock) {
        make_script_path_spend_with(&[0x51], &[])
    }

    fn make_script_path_spend_with(
        leaf_bytes: &[u8],
        stack_items: &[&[u8]],
    ) -> (ScriptCheckJob, ControlBlock) {
        let secp = Secp256k1::new();
        let internal_sk = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let internal_kp = Keypair::from_secret_key(&secp, &internal_sk);
        let (internal_xonly, _) = internal_kp.x_only_public_key();

        let leaf = ScriptBuf::from_bytes(leaf_bytes.to_vec());
        let builder = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("leaf");
        let spend_info = builder.finalize(&secp, internal_xonly).expect("finalize");
        let output_key = spend_info.output_key().to_x_only_public_key();
        let control = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control");

        assert!(control.verify_taproot_commitment(&secp, output_key, leaf.as_script()));

        let ctrl = control.serialize();
        let mut wit: Vec<&[u8]> = stack_items.to_vec();
        wit.push(leaf.as_bytes());
        wit.push(ctrl.as_slice());

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
                witness: Witness::from_slice(&wit),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let job = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: crate::block::JobPrevouts::owned(vec![prevout]),
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
        (job, control)
    }

    #[test]
    fn script_path_accepts_with_valid_bip341_tweak() {
        let (job, _) = make_script_path_spend();
        script::verify_job_all_inputs(&job).expect("p2tr script path");
    }

    /// Future leaf `0xc2` and annex leaf `0x50` commit and succeed. Tapscript still runs.
    #[test]
    fn script_path_accepts_leaf_0x50_with_annex_and_0xc2() {
        use bitcoin::consensus::Encodable;
        use bitcoin::key::TapTweak;
        use bitcoin::secp256k1::Parity;

        fn job_for(leaf_ver: u8, annex: bool) -> ScriptCheckJob {
            let secp = Secp256k1::new();
            let internal_sk = SecretKey::from_slice(&[3u8; 32]).unwrap();
            let internal_kp = Keypair::from_secret_key(&secp, &internal_sk);
            let (internal, _) = internal_kp.x_only_public_key();
            let leaf = ScriptBuf::from_bytes(vec![0x51]);
            let mut eng = TapLeafHash::engine();
            leaf_ver.consensus_encode(&mut eng).expect("engine");
            leaf.as_script().consensus_encode(&mut eng).expect("engine");
            let node = TapNodeHash::from_byte_array(TapLeafHash::from_engine(eng).to_byte_array());
            let (tweaked, parity) = internal.tap_tweak(&secp, Some(node));
            let output_key = tweaked.to_x_only_public_key();
            let parity_bit = match parity {
                Parity::Even => 0u8,
                Parity::Odd => 1,
            };
            let mut control = Vec::with_capacity(33);
            control.push(leaf_ver | parity_bit);
            control.extend_from_slice(&internal.serialize());
            let mut wit = vec![leaf.as_bytes().to_vec(), control];
            if annex {
                wit.push(vec![0x50, 0x01]);
            }
            let refs: Vec<&[u8]> = wit.iter().map(|v| v.as_slice()).collect();
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
                    witness: Witness::from_slice(&refs),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(49_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            };
            ScriptCheckJob {
                txid: [0u8; 32],
                prevouts: crate::block::JobPrevouts::owned(vec![prevout]),
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

        script::verify_job_all_inputs(&job_for(0xc2, false)).expect("leaf 0xc2");
        script::verify_job_all_inputs(&job_for(0x50, true)).expect("leaf 0x50 with annex");
    }

    /// Core ExecuteWitnessScript (TAPSCRIPT): initial stack > 1000 is
    /// SCRIPT_ERR_STACK_SIZE even if the leaf would drain it.
    #[test]
    fn script_path_rejects_initial_stack_over_max_size() {
        let ones: Vec<Vec<u8>> = (0..1001).map(|_| vec![0x01]).collect();
        let refs: Vec<&[u8]> = ones.iter().map(|v| v.as_slice()).collect();
        let leaf: Vec<u8> = vec![0x75; 1000];
        let (job, _) = make_script_path_spend_with(&leaf, &refs);
        let err = script::verify_job_all_inputs(&job).expect_err("1001 initial stack");
        let msg = format!("{err}");
        assert!(msg.contains("stack size"), "expected stack size, got {msg}");
    }

    #[test]
    fn script_path_rejects_tapscript_validation_weight() {
        let dummy = vec![0x01u8];
        let sigs3: [&[u8]; 3] = [&dummy, &dummy, &dummy];
        let leaf3: Vec<u8> = [
            0x01, 0xaa, 0xac, 0x75, 0x01, 0xaa, 0xac, 0x75, 0x01, 0xaa, 0xac,
        ]
        .to_vec();
        let (job, _) = make_script_path_spend_with(&leaf3, &sigs3);
        let err = script::verify_job_all_inputs(&job).expect_err("3 CHECKSIGs over budget");
        let msg = format!("{err}");
        assert!(
            msg.contains("validation weight"),
            "expected validation weight, got {msg}"
        );

        let leaf1 = [0x01u8, 0xaa, 0xac];
        let (job, _) = make_script_path_spend_with(&leaf1, &[&dummy]);
        script::verify_job_all_inputs(&job).expect("1 CHECKSIG within budget");
    }

    /// Tapscript has no opcode limit, so `(OP_1 OP_IF)×K OP_1 OP_ENDIF×K` must
    /// cost O(K) like Core's `ConditionStack`, not O(K²). At this depth a
    /// per-opcode scan of the condition stack runs for tens of seconds.
    #[test]
    fn script_path_deep_if_nesting_verifies_in_linear_time() {
        const DEPTH: usize = 100_000;
        let mut leaf = [0x51u8, 0x63].repeat(DEPTH);
        leaf.push(0x51);
        leaf.extend(std::iter::repeat_n(0x68u8, DEPTH));

        let (job, _) = make_script_path_spend_with(&leaf, &[]);
        let started = std::time::Instant::now();
        script::verify_job_all_inputs(&job).expect("deep nested IF");
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "deep IF nesting took {elapsed:?}"
        );

        leaf.pop();
        let (job, _) = make_script_path_spend_with(&leaf, &[]);
        let err = script::verify_job_all_inputs(&job).expect_err("one ENDIF short");
        assert!(format!("{err}").contains("unbalanced IF"), "{err}");
    }

    /// Core ExecuteWitnessScript: every initial tapscript witness element ≤ 520.
    #[test]
    fn script_path_rejects_initial_element_over_520() {
        let true_item = vec![0x01];
        let big = vec![0u8; 521];
        let (job, _) =
            make_script_path_spend_with(&[0x75], &[true_item.as_slice(), big.as_slice()]);
        let err = script::verify_job_all_inputs(&job).expect_err("521-byte initial element");
        let msg = format!("{err}");
        assert!(
            msg.contains("PUSH_SIZE") || msg.contains("push too large"),
            "expected PUSH_SIZE-class, got {msg}"
        );
    }

    /// BIP342: OP_SUCCESS overrides initial-stack count and element-size limits.
    #[test]
    fn script_path_op_success_overrides_initial_stack_limits() {
        let ones: Vec<Vec<u8>> = (0..1001).map(|_| vec![0x01]).collect();
        let refs: Vec<&[u8]> = ones.iter().map(|v| v.as_slice()).collect();
        let (job, _) = make_script_path_spend_with(&[0x50], &refs);
        script::verify_job_all_inputs(&job).expect("OP_SUCCESS + 1001 stack");

        let true_item = vec![0x01];
        let big = vec![0u8; 521];
        let (job, _) =
            make_script_path_spend_with(&[0x50], &[true_item.as_slice(), big.as_slice()]);
        script::verify_job_all_inputs(&job).expect("OP_SUCCESS + 521-byte element");
    }

    #[test]
    fn script_path_rejects_wrong_output_key() {
        let (mut job, _) = make_script_path_spend();
        // Flip a byte in the prevout output key → BIP341 commitment fails.
        let spk = owned_prevout_mut(&mut job).script_pubkey.as_bytes();
        let mut bad = spk.to_vec();
        bad[10] ^= 0x01;
        owned_prevout_mut(&mut job).script_pubkey = ScriptBuf::from_bytes(bad);
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

    /// Two merkle nodes, so the path offset `33 + i * 32` is not a no-op.
    #[test]
    fn script_path_accepts_two_merkle_nodes() {
        let secp = Secp256k1::new();
        let internal_sk = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let internal_kp = Keypair::from_secret_key(&secp, &internal_sk);
        let (internal_xonly, _) = internal_kp.x_only_public_key();
        let leaf = ScriptBuf::from_bytes(vec![0x51]);
        let spend_info = TaprootBuilder::new()
            .add_leaf(2, leaf.clone())
            .expect("leaf")
            .add_leaf(2, ScriptBuf::from_bytes(vec![0x52]))
            .expect("sibling")
            .add_leaf(1, ScriptBuf::from_bytes(vec![0x53]))
            .expect("side")
            .finalize(&secp, internal_xonly)
            .expect("finalize");
        let output_key = spend_info.output_key().to_x_only_public_key();
        let control = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control");
        let ctrl = control.serialize();
        assert_eq!(ctrl.len(), 33 + 64, "two merkle nodes");
        let (mut job, _) = make_script_path_spend();
        let script = job.tx.input[0].witness.nth(0).unwrap().to_vec();
        job.tx.input[0].witness = Witness::from_slice(&[script.as_slice(), ctrl.as_slice()]);
        owned_prevout_mut(&mut job).script_pubkey = p2tr_spk(output_key);
        script::verify_job_all_inputs(&job).expect("two-node script path");
    }

    fn control_size_error(control: &[u8]) -> String {
        let (mut job, _) = make_script_path_spend();
        let script = job.tx.input[0].witness.nth(0).unwrap().to_vec();
        job.tx.input[0].witness = Witness::from_slice(&[script.as_slice(), control]);
        format!(
            "{}",
            script::verify_job_all_inputs(&job).expect_err("control")
        )
    }

    #[test]
    fn control_block_size_bounds() {
        let (job, _) = make_script_path_spend();
        let base = job.tx.input[0].witness.nth(1).unwrap().to_vec();
        assert_eq!(base.len(), 33);

        let mut short = base.clone();
        short.pop();
        assert!(
            control_size_error(&short).contains("TAPROOT_WRONG_CONTROL_SIZE"),
            "32-byte control"
        );

        let mut odd = base.clone();
        odd.push(0);
        assert!(
            control_size_error(&odd).contains("TAPROOT_WRONG_CONTROL_SIZE"),
            "34-byte control"
        );

        let mut deep = base.clone();
        deep.extend(vec![0x11u8; 128 * 32]);
        let msg = control_size_error(&deep);
        assert!(
            msg.contains("WITNESS_PROGRAM_MISMATCH"),
            "128 nodes are in range, got {msg}"
        );
        assert!(
            !msg.contains("TAPROOT_WRONG_CONTROL_SIZE"),
            "128 nodes are in range, got {msg}"
        );

        let mut too_deep = base.clone();
        too_deep.extend(vec![0x11u8; 129 * 32]);
        assert!(
            control_size_error(&too_deep).contains("TAPROOT_WRONG_CONTROL_SIZE"),
            "129 nodes"
        );
    }

    #[test]
    fn empty_witness_and_bad_sig_len() {
        let mut spk = vec![0x51, 0x20];
        spk.extend([0u8; 32]);
        let job = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: crate::block::JobPrevouts::owned(vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(spk),
            }]),
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
        assert!(verify(&job, 0, &job.tx, &Default::default()).is_err());

        let mut job2 = job;
        job2.tx.input[0].witness = Witness::from_slice(&[vec![0u8; 10]]);
        assert!(verify(&job2, 0, &job2.tx, &Default::default()).is_err());
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
            prevouts: crate::block::JobPrevouts::owned(vec![prevout]),
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
        script::verify_job_all_inputs(&job).expect("p2tr key path");
    }

    /// One key-path spend; `corrupt` flips a bit in the signature.
    fn key_path_job(seed: u8, corrupt: bool) -> ScriptCheckJob {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap());
        let tweaked: TweakedKeypair = kp.tap_tweak(&secp, None);
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2tr_spk(tweaked.to_keypair().x_only_public_key().0),
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
                value: Amount::from_sat(u64::from(seed) * 1_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let sighash = SighashCache::new(&tx)
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(&prevout)),
                TapSighashType::Default,
            )
            .unwrap();
        let sig = secp.sign_schnorr_no_aux_rand(
            &Message::from_digest(sighash.to_byte_array()),
            &tweaked.to_keypair(),
        );
        let mut sig = sig.serialize();
        if corrupt {
            sig[63] ^= 1;
        }
        tx.input[0].witness = Witness::from_slice(&[sig.as_slice()]);
        ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: crate::block::JobPrevouts::owned(vec![prevout]),
            tx: crate::block::JobTx::owned(tx),
            flags: crate::block::ScriptVerifyFlags::buried(true, true, true, true, true),
            pre: std::sync::OnceLock::new(),
        }
    }

    fn run_chunk(jobs: &[ScriptCheckJob]) -> Result<(), ConsensusError> {
        crate::script::batch::batched(|| {
            jobs.iter()
                .try_for_each(crate::block::verify_one_script_job)
        })
    }

    /// A block chunk shares one batch. A bad key-path signature fails it, and
    /// the error names the spend that carried it.
    #[test]
    fn batched_chunk_names_the_bad_key_path_spend() {
        let good: Vec<_> = (10..16).map(|s| key_path_job(s, false)).collect();
        run_chunk(&good).expect("valid chunk");
        let jobs: Vec<_> = (10..16).map(|s| key_path_job(s, s == 13)).collect();
        let msg = run_chunk(&jobs).expect_err("bad signature").to_string();
        let bad_txid = jobs[3].tx.compute_txid().to_string();
        assert!(msg.contains("p2tr schnorr"), "{msg}");
        assert!(msg.contains(&bad_txid), "{msg}");
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
            prevouts: crate::block::JobPrevouts::owned(vec![prevout]),
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
                prevouts: crate::block::JobPrevouts::owned(vec![prevout.clone()]),
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
                prevouts: crate::block::JobPrevouts::owned(vec![prevout]),
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
            prevouts: crate::block::JobPrevouts::owned(vec![prevout]),
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
            prevouts: crate::block::JobPrevouts::owned(vec![prevout]),
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
        };
        script::verify_job_all_inputs(&job).expect("script path + annex CHECKSIG");
    }

    /// Core hashes the tapleaf, the annex, and the SIGHASH_SINGLE output once
    /// per input (`ScriptExecutionData`). Rehashing them on every signature
    /// opcode makes a large leaf, annex, or output cost O(sigs × size), and
    /// the validation weight budget grows with that same witness size.
    #[test]
    fn script_path_many_sigs_hash_leaf_annex_and_output_once() {
        use bitcoin::sighash::Annex;
        use bitcoin::taproot::LeafVersion;

        const SIGS: usize = 1_000;
        const PAD: usize = 1 << 20;

        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[11u8; 32]).unwrap());
        let pk = kp.x_only_public_key().0.serialize();
        let mut push_pk = vec![0x20];
        push_pk.extend_from_slice(&pk);

        let mut leaf_bytes = Vec::with_capacity(PAD + SIGS * 36);
        let mut drop_520 = vec![0x4d, 0x08, 0x02];
        drop_520.extend_from_slice(&[0xab; 520]);
        drop_520.push(0x75);
        while leaf_bytes.len() < PAD {
            leaf_bytes.extend_from_slice(&drop_520);
        }
        for _ in 1..SIGS {
            leaf_bytes.push(0x76);
            leaf_bytes.extend_from_slice(&push_pk);
            leaf_bytes.push(0xad);
        }
        leaf_bytes.extend_from_slice(&push_pk);
        leaf_bytes.push(0xac);
        let leaf = ScriptBuf::from_bytes(leaf_bytes);

        let internal =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[12u8; 32]).unwrap())
                .x_only_public_key()
                .0;
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("leaf")
            .finalize(&secp, internal)
            .expect("finalize");
        let control = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control");
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2tr_spk(spend_info.output_key().to_x_only_public_key()),
        };
        let mut annex_bytes = vec![0x50];
        annex_bytes.resize(PAD, 0xcd);
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
                script_pubkey: ScriptBuf::from_bytes(vec![0x6a; PAD]),
            }],
        };
        let sighash = SighashCache::new(&tx)
            .taproot_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(&prevout)),
                Some(Annex::new(&annex_bytes).unwrap()),
                Some((
                    TapLeafHash::from_script(&leaf, LeafVersion::TapScript),
                    0xFFFF_FFFF,
                )),
                TapSighashType::Single,
            )
            .unwrap();
        let mut sig = secp
            .sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), &kp)
            .as_ref()
            .to_vec();
        sig.push(TapSighashType::Single as u8);
        tx.input[0].witness = Witness::from_slice(&[
            sig.as_slice(),
            leaf.as_bytes(),
            control.serialize().as_slice(),
            annex_bytes.as_slice(),
        ]);
        let job = ScriptCheckJob::new(
            vec![prevout],
            tx,
            crate::block::ScriptVerifyFlags::buried(true, true, true, true, true),
        );

        let started = std::time::Instant::now();
        script::verify_job_all_inputs(&job).expect("many sigs over large leaf, annex, output");
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "{SIGS} sigs took {elapsed:?}"
        );
    }

    /// Core hashes the spent amounts and scriptPubKeys once per tx
    /// (`PrecomputedTransactionData`). Rehashing them for every script-path
    /// input that checks a signature costs O(inputs × spent script bytes).
    #[test]
    fn script_path_many_inputs_hash_spent_outputs_once() {
        const TAP_INPUTS: usize = 500;
        const BIG_INPUTS: usize = 200;

        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[13u8; 32]).unwrap());
        let mut leaf_bytes = vec![0x20];
        leaf_bytes.extend_from_slice(&kp.x_only_public_key().0.serialize());
        leaf_bytes.push(0xac);
        let leaf = ScriptBuf::from_bytes(leaf_bytes);
        let internal =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[14u8; 32]).unwrap())
                .x_only_public_key()
                .0;
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("leaf")
            .finalize(&secp, internal)
            .expect("finalize");
        let control = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control")
            .serialize();
        let tap_prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2tr_spk(spend_info.output_key().to_x_only_public_key()),
        };
        // `OP_0 OP_IF <520-byte push>×19 OP_ENDIF OP_1`: a 9941-byte bare
        // scriptPubKey that an empty scriptSig spends.
        let mut big_spk = vec![0x00, 0x63];
        for _ in 0..19 {
            big_spk.extend_from_slice(&[0x4d, 0x08, 0x02]);
            big_spk.extend_from_slice(&[0xab; 520]);
        }
        big_spk.extend_from_slice(&[0x68, 0x51]);
        let big_prevout = TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(big_spk),
        };

        let prevouts: Vec<TxOut> = std::iter::repeat_n(tap_prevout, TAP_INPUTS)
            .chain(std::iter::repeat_n(big_prevout, BIG_INPUTS))
            .collect();
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: (0..prevouts.len())
                .map(|i| TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::from_byte_array([1; 32]),
                        vout: i as u32,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let mut cache = SighashCache::new(tx.clone());
        let witnesses: Vec<Witness> = (0..TAP_INPUTS)
            .map(|i| {
                let sighash = cache
                    .taproot_script_spend_signature_hash(
                        i,
                        &Prevouts::All(&prevouts),
                        leaf_hash,
                        TapSighashType::Default,
                    )
                    .unwrap();
                let sig = secp
                    .sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), &kp);
                Witness::from_slice(&[sig.as_ref().as_slice(), leaf.as_bytes(), &control])
            })
            .collect();
        for (input, witness) in tx.input.iter_mut().zip(witnesses) {
            input.witness = witness;
        }
        let job = ScriptCheckJob::new(
            prevouts,
            tx,
            crate::block::ScriptVerifyFlags::buried(true, true, true, true, true),
        );

        let started = std::time::Instant::now();
        script::verify_job_all_inputs(&job).expect("many script-path inputs, large spent scripts");
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "{TAP_INPUTS} script-path inputs took {elapsed:?}"
        );
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
            prevouts: crate::block::JobPrevouts::owned(vec![prevout]),
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
            prevouts: crate::block::JobPrevouts::owned(vec![prevout]),
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
            prevouts: crate::block::JobPrevouts::owned(vec![prevout]),
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
        assert!(script::verify_job_all_inputs(&job).is_err());
    }
}
