//! Deferred BIP340 signature and BIP341 tweak checks for block confirm.
//!
//! Inside [`batched`], [`verify_schnorr`] and [`tweak_add_check`] queue the
//! check on this thread's batch and report success. The batch is verified when
//! the closure returns. Every Taproot check routed here fails the spend when it
//! fails (BIP341 key path, BIP342 non-empty signature, control-block
//! commitment), so a deferred check cannot turn an invalid spend valid: the
//! batch fails instead. Outside [`batched`] (mempool, RPC) each check runs at
//! once.

use std::cell::RefCell;

use bitcoin::secp256k1::{schnorr, Message, Parity, Scalar, XOnlyPublicKey};
use rbitcoin_secp256k1_batch::{Batch, XOnlyPublicKey as BatchKey};

use super::crypto;
use crate::error::ConsensusError;

enum Pending {
    /// No [`batched`] scope on this thread: check at once.
    Off,
    /// Queue checks. The batch is allocated on the first one.
    On(Option<Batch>),
}

thread_local! {
    static PENDING: RefCell<Pending> = const { RefCell::new(Pending::Off) };
}

/// Ends the scope even when `f` panics.
struct Scope;

impl Scope {
    fn open() -> Self {
        PENDING.set(Pending::On(None));
        Scope
    }

    fn close(self) -> Option<Batch> {
        match PENDING.replace(Pending::Off) {
            Pending::On(batch) => batch,
            Pending::Off => None,
        }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        PENDING.set(Pending::Off);
    }
}

/// Run `f` with Taproot checks queued, then verify them together.
///
/// A failed batch does not say which check failed, so `f` runs again with each
/// check done at once. That run names the failing input and decides the result.
pub(crate) fn batched(f: impl Fn() -> Result<(), ConsensusError>) -> Result<(), ConsensusError> {
    if PENDING.with_borrow(|p| matches!(p, Pending::On(_))) {
        return f();
    }
    let scope = Scope::open();
    let res = f();
    let batch = scope.close();
    res?;
    if batch.is_none_or(Batch::verify) {
        return Ok(());
    }
    f()
}

/// BIP340 verify of `sig` over `msg` for the x-only key `pubkey`.
pub(crate) fn verify_schnorr(sig: &[u8; 64], msg: &[u8; 32], pubkey: &[u8; 32]) -> bool {
    PENDING.with_borrow_mut(|p| match p {
        Pending::On(batch) => {
            let Some(pubkey) = BatchKey::from_bytes(pubkey) else {
                return false;
            };
            batch
                .get_or_insert_with(Batch::new)
                .add_schnorrsig(sig, msg, &pubkey);
            true
        }
        Pending::Off => {
            let (Ok(pubkey), Ok(sig)) = (
                XOnlyPublicKey::from_slice(pubkey),
                schnorr::Signature::from_slice(sig),
            ) else {
                return false;
            };
            let msg = Message::from_digest(*msg);
            crypto::SECP.with(|secp| secp.verify_schnorr(&sig, &msg, &pubkey).is_ok())
        }
    })
}

/// BIP341 commitment: `output` (y parity `odd`) is `internal + tweak·G`.
pub(crate) fn tweak_add_check(
    output: &[u8; 32],
    odd: bool,
    internal: &[u8; 32],
    tweak: &[u8; 32],
) -> bool {
    PENDING.with_borrow_mut(|p| match p {
        Pending::On(batch) => {
            let Some(internal) = BatchKey::from_bytes(internal) else {
                return false;
            };
            batch
                .get_or_insert_with(Batch::new)
                .add_tweak_check(output, odd, &internal, tweak);
            true
        }
        Pending::Off => {
            let (Ok(internal), Ok(output), Ok(tweak)) = (
                XOnlyPublicKey::from_slice(internal),
                XOnlyPublicKey::from_slice(output),
                Scalar::from_be_bytes(*tweak),
            ) else {
                return false;
            };
            let parity = if odd { Parity::Odd } else { Parity::Even };
            crypto::SECP.with(|secp| internal.tweak_add_check(secp, &output, parity, tweak))
        }
    })
}

/// Verify `job` input by input and again under [`batched`]. The two verdicts
/// must agree; returns the input-by-input result.
#[cfg(test)]
pub(crate) fn verify_job_both_ways(
    job: &crate::block::ScriptCheckJob,
) -> Result<(), ConsensusError> {
    let each = super::verify_job_all_inputs(job);
    let together = batched(|| super::verify_job_all_inputs(job));
    assert_eq!(
        each.is_ok(),
        together.is_ok(),
        "batched verdict differs: each={each:?} batched={together:?}"
    );
    each
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::key::{Keypair, TapTweak};
    use bitcoin::secp256k1::Secp256k1;
    use std::cell::RefCell;

    struct Signed {
        sig: [u8; 64],
        msg: [u8; 32],
        pubkey: [u8; 32],
    }

    fn signed() -> Signed {
        let secp = Secp256k1::new();
        let kp = Keypair::from_seckey_slice(&secp, &[5; 32]).unwrap();
        let msg = [9; 32];
        let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(msg), &kp);
        Signed {
            sig: sig.serialize(),
            msg,
            pubkey: kp.x_only_public_key().0.serialize(),
        }
    }

    /// Run `check` under [`batched`], recording what it returned on each pass.
    fn passes(check: impl Fn() -> bool) -> (Result<(), ConsensusError>, Vec<bool>) {
        let seen = RefCell::new(Vec::new());
        let res = batched(|| {
            let ok = check();
            seen.borrow_mut().push(ok);
            if ok {
                Ok(())
            } else {
                Err(ConsensusError::Script("check failed".into()))
            }
        });
        (res, seen.into_inner())
    }

    fn assert_check_failed(res: Result<(), ConsensusError>) {
        let msg = res.expect_err("check must fail").to_string();
        assert!(msg.contains("check failed"), "{msg}");
    }

    #[test]
    fn valid_signature_passes_in_one_run() {
        let s = signed();
        let (res, seen) = passes(|| verify_schnorr(&s.sig, &s.msg, &s.pubkey));
        res.unwrap();
        assert_eq!(seen, [true]);
    }

    /// The bad signature is queued (reported true), the batch fails, and the
    /// rerun checks it at once.
    #[test]
    fn bad_signature_is_queued_then_named_by_the_rerun() {
        let s = signed();
        let bad = [8; 32];
        let (res, seen) = passes(|| verify_schnorr(&s.sig, &bad, &s.pubkey));
        assert_check_failed(res);
        assert_eq!(seen, [true, false]);
        assert!(!verify_schnorr(&s.sig, &bad, &s.pubkey), "scope is closed");
    }

    #[test]
    fn off_curve_key_fails_at_once_in_a_batch() {
        let s = signed();
        let (res, seen) = passes(|| verify_schnorr(&s.sig, &s.msg, &[0xff; 32]));
        assert_check_failed(res);
        assert_eq!(seen, [false]);
    }

    fn tweak_case() -> ([u8; 32], bool, [u8; 32], [u8; 32]) {
        use bitcoin::hashes::Hash;
        let secp = Secp256k1::new();
        let kp = Keypair::from_seckey_slice(&secp, &[6; 32]).unwrap();
        let internal = kp.x_only_public_key().0;
        let root = bitcoin::taproot::TapNodeHash::assume_hidden([7; 32]);
        let tweak = bitcoin::taproot::TapTweakHash::from_key_and_tweak(internal, Some(root));
        let (output, parity) = internal.tap_tweak(&secp, Some(root));
        (
            output.to_x_only_public_key().serialize(),
            parity == Parity::Odd,
            internal.serialize(),
            tweak.to_byte_array(),
        )
    }

    #[test]
    fn tweak_checks_queue_and_a_bad_parity_reruns() {
        let (output, odd, internal, tweak) = tweak_case();
        let (res, seen) = passes(|| tweak_add_check(&output, odd, &internal, &tweak));
        res.unwrap();
        assert_eq!(seen, [true]);
        let (res, seen) = passes(|| tweak_add_check(&output, !odd, &internal, &tweak));
        assert_check_failed(res);
        assert_eq!(seen, [true, false]);
    }

    /// A tweak at or above the group order fails instead of panicking.
    #[test]
    fn overflowing_tweak_fails() {
        let (output, odd, internal, _) = tweak_case();
        assert!(!tweak_add_check(&output, odd, &internal, &[0xff; 32]));
        let (res, _) = passes(|| tweak_add_check(&output, odd, &internal, &[0xff; 32]));
        assert_check_failed(res);
    }

    #[test]
    fn nested_scope_defers_to_the_outer_batch() {
        let s = signed();
        let bad = [8; 32];
        let (res, seen) = passes(|| {
            batched(|| {
                if verify_schnorr(&s.sig, &bad, &s.pubkey) {
                    Ok(())
                } else {
                    Err(ConsensusError::Script("inner".into()))
                }
            })
            .is_ok()
        });
        assert_check_failed(res);
        assert_eq!(seen, [true, false]);
    }

    #[test]
    fn scope_closes_when_the_closure_panics() {
        let s = signed();
        let bad = [8; 32];
        let caught = std::panic::catch_unwind(|| batched(|| panic!("boom")));
        caught.expect_err("the panic reaches the caller");
        assert!(
            !verify_schnorr(&s.sig, &bad, &s.pubkey),
            "checks run at once"
        );
    }
}
