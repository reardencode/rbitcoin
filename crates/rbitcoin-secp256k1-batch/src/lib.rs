//! Batch verification of BIP340 Schnorr signatures and BIP341 x-only tweak
//! checks.
//!
//! Wraps the batch module from bitcoin-core/secp256k1 PR #1134 (not merged
//! upstream), vendored under `depend/` by `vendor-libsecp.sh`. The C symbols
//! carry an `rbtc_secp256k1_` prefix so this copy links next to rust-bitcoin's
//! `secp256k1-sys`.
//!
//! [`Batch::verify`] is true only when every added check would pass on its
//! own. A false result does not say which check failed; re-check one at a time
//! for that.

use std::ffi::c_int;
use std::ptr::NonNull;
use std::sync::Once;

mod ffi {
    use std::ffi::c_int;

    #[repr(C)]
    pub struct Context {
        _private: [u8; 0],
    }

    #[repr(C)]
    pub struct Batch {
        _private: [u8; 0],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct XOnlyPublicKey(pub [u8; 64]);

    extern "C" {
        pub static rbtc_secp256k1_context_static: *const Context;

        pub fn rbtc_secp256k1_selftest();

        pub fn rbtc_secp256k1_xonly_pubkey_parse(
            ctx: *const Context,
            pubkey: *mut XOnlyPublicKey,
            input32: *const u8,
        ) -> c_int;

        pub fn rbtc_secp256k1_batch_create(
            ctx: *const Context,
            max_terms: usize,
            aux_rand16: *const u8,
        ) -> *mut Batch;

        pub fn rbtc_secp256k1_batch_destroy(ctx: *const Context, batch: *mut Batch);

        pub fn rbtc_secp256k1_batch_verify(ctx: *const Context, batch: *mut Batch) -> c_int;

        pub fn rbtc_secp256k1_batch_add_schnorrsig(
            ctx: *const Context,
            batch: *mut Batch,
            sig64: *const u8,
            msg: *const u8,
            msglen: usize,
            pubkey: *const XOnlyPublicKey,
        );

        pub fn rbtc_secp256k1_batch_add_xonlypub_tweak_check(
            ctx: *const Context,
            batch: *mut Batch,
            tweaked_pubkey32: *const u8,
            tweaked_pk_parity: c_int,
            internal_pubkey: *const XOnlyPublicKey,
            tweak32: *const u8,
        );
    }
}

/// libsecp caps a batch at this many scalar-point terms and verifies early
/// when it fills. A signature takes two terms, a tweak check one.
const MAX_TERMS: usize = 106;

fn ctx() -> *const ffi::Context {
    static SELFTEST: Once = Once::new();
    // SAFETY: the selftest takes no arguments and aborts on failure.
    SELFTEST.call_once(|| unsafe { ffi::rbtc_secp256k1_selftest() });
    // SAFETY: a `const` pointer that C initializes before `main`.
    unsafe { ffi::rbtc_secp256k1_context_static }
}

/// A BIP340 x-only public key, parsed by the vendored library.
#[derive(Clone, Copy)]
pub struct XOnlyPublicKey(ffi::XOnlyPublicKey);

impl XOnlyPublicKey {
    /// `None` when `bytes` is not the x coordinate of a curve point.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let mut pk = ffi::XOnlyPublicKey([0; 64]);
        // SAFETY: `pk` and `bytes` are valid for the sizes libsecp reads.
        let ok = unsafe { ffi::rbtc_secp256k1_xonly_pubkey_parse(ctx(), &mut pk, bytes.as_ptr()) };
        (ok == 1).then_some(Self(pk))
    }
}

/// Collects checks and verifies them all at once.
///
/// Randomizers are derived from 16 fresh random bytes plus every input added
/// so far, so a block author cannot make invalid checks cancel out.
pub struct Batch {
    ptr: NonNull<ffi::Batch>,
}

// SAFETY: the batch owns its heap state and nothing in it is thread-bound.
unsafe impl Send for Batch {}

impl Default for Batch {
    fn default() -> Self {
        Self::new()
    }
}

impl Batch {
    /// An empty batch seeded with fresh process randomness.
    pub fn new() -> Self {
        let aux = aux_rand16();
        // SAFETY: `aux` is 16 readable bytes; a null return is handled.
        let raw = unsafe { ffi::rbtc_secp256k1_batch_create(ctx(), MAX_TERMS, aux.as_ptr()) };
        let ptr = NonNull::new(raw).expect("secp256k1 batch allocation");
        Self { ptr }
    }

    /// Queue a BIP340 check of `sig` over the 32-byte `msg`.
    pub fn add_schnorrsig(&mut self, sig: &[u8; 64], msg: &[u8; 32], pubkey: &XOnlyPublicKey) {
        // SAFETY: every pointer is valid for the length libsecp reads; the
        // batch copies what it needs before returning.
        unsafe {
            ffi::rbtc_secp256k1_batch_add_schnorrsig(
                ctx(),
                self.ptr.as_ptr(),
                sig.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                &pubkey.0,
            )
        }
    }

    /// Queue a BIP341 check that `tweaked` (with y parity `tweaked_odd`) is
    /// `internal + tweak·G`.
    pub fn add_tweak_check(
        &mut self,
        tweaked: &[u8; 32],
        tweaked_odd: bool,
        internal: &XOnlyPublicKey,
        tweak: &[u8; 32],
    ) {
        // SAFETY: as in `add_schnorrsig`.
        unsafe {
            ffi::rbtc_secp256k1_batch_add_xonlypub_tweak_check(
                ctx(),
                self.ptr.as_ptr(),
                tweaked.as_ptr(),
                c_int::from(tweaked_odd),
                &internal.0,
                tweak.as_ptr(),
            )
        }
    }

    /// True when every queued check is valid. An empty batch is valid.
    pub fn verify(self) -> bool {
        // SAFETY: `self.ptr` is a live batch; `Drop` frees it afterwards.
        unsafe { ffi::rbtc_secp256k1_batch_verify(ctx(), self.ptr.as_ptr()) == 1 }
    }
}

impl Drop for Batch {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` came from `batch_create` and is freed only here.
        unsafe { ffi::rbtc_secp256k1_batch_destroy(ctx(), self.ptr.as_ptr()) }
    }
}

/// 16 bytes from std's OS-seeded SipHash keys. No extra RNG dependency.
fn aux_rand16() -> [u8; 16] {
    use std::hash::BuildHasher;
    let half = || std::collections::hash_map::RandomState::new().hash_one(0u8);
    (u128::from(half()) << 64 | u128::from(half())).to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::key::{Keypair, TapTweak, UntweakedPublicKey};
    use bitcoin::secp256k1::{Message, Secp256k1};
    use bitcoin::taproot::TapNodeHash;

    struct Sig {
        sig: [u8; 64],
        msg: [u8; 32],
        pk: [u8; 32],
    }

    fn sigs(n: u8) -> Vec<Sig> {
        let secp = Secp256k1::new();
        (1..=n)
            .map(|i| {
                let kp = Keypair::from_seckey_slice(&secp, &[i; 32]).unwrap();
                let msg = [i.wrapping_mul(7); 32];
                let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(msg), &kp);
                Sig {
                    sig: sig.serialize(),
                    msg,
                    pk: kp.x_only_public_key().0.serialize(),
                }
            })
            .collect()
    }

    fn batch_of(sigs: &[Sig]) -> bool {
        let mut batch = Batch::new();
        for s in sigs {
            let pk = XOnlyPublicKey::from_bytes(&s.pk).unwrap();
            batch.add_schnorrsig(&s.sig, &s.msg, &pk);
        }
        batch.verify()
    }

    #[test]
    fn empty_batch_verifies() {
        assert!(Batch::new().verify());
    }

    /// 60 signatures take 120 terms, past the 106-term early verify.
    #[test]
    fn valid_signatures_verify_across_the_term_cap() {
        assert!(batch_of(&sigs(1)));
        assert!(batch_of(&sigs(60)));
    }

    #[test]
    fn one_bad_signature_fails_the_batch_wherever_it_sits() {
        for bad in [0, 30, 52, 53, 59] {
            let mut v = sigs(60);
            v[bad].msg[0] ^= 1;
            assert!(!batch_of(&v), "bad signature at {bad}");
        }
    }

    #[test]
    fn out_of_range_signature_fails() {
        let mut v = sigs(3);
        v[1].sig[32..].copy_from_slice(&[0xff; 32]);
        assert!(!batch_of(&v), "s >= n");
        let mut v = sigs(3);
        v[2].sig[..32].copy_from_slice(&[0xff; 32]);
        assert!(!batch_of(&v), "r >= p");
    }

    #[test]
    fn xonly_parse_rejects_off_curve_x() {
        assert!(XOnlyPublicKey::from_bytes(&[0xff; 32]).is_none());
        assert!(XOnlyPublicKey::from_bytes(&sigs(1)[0].pk).is_some());
    }

    struct Tweak {
        output: [u8; 32],
        odd: bool,
        internal: [u8; 32],
        tweak: [u8; 32],
    }

    fn tweaks(n: u8) -> Vec<Tweak> {
        let secp = Secp256k1::new();
        (1..=n)
            .map(|i| {
                let kp = Keypair::from_seckey_slice(&secp, &[i; 32]).unwrap();
                let internal: UntweakedPublicKey = kp.x_only_public_key().0;
                let root = TapNodeHash::assume_hidden([i; 32]);
                let tweak =
                    bitcoin::taproot::TapTweakHash::from_key_and_tweak(internal, Some(root));
                let (output, parity) = internal.tap_tweak(&secp, Some(root));
                Tweak {
                    output: output.to_x_only_public_key().serialize(),
                    odd: parity == bitcoin::secp256k1::Parity::Odd,
                    internal: internal.serialize(),
                    tweak: tweak.to_byte_array(),
                }
            })
            .collect()
    }

    fn tweak_batch_of(v: &[Tweak]) -> bool {
        let mut batch = Batch::new();
        for t in v {
            let internal = XOnlyPublicKey::from_bytes(&t.internal).unwrap();
            batch.add_tweak_check(&t.output, t.odd, &internal, &t.tweak);
        }
        batch.verify()
    }

    #[test]
    fn tweak_checks_verify_and_reject_a_bad_parity_or_tweak() {
        assert!(tweak_batch_of(&tweaks(120)));
        let mut v = tweaks(120);
        v[110].odd = !v[110].odd;
        assert!(!tweak_batch_of(&v), "wrong parity");
        let mut v = tweaks(8);
        v[3].tweak[31] ^= 1;
        assert!(!tweak_batch_of(&v), "wrong tweak");
    }

    #[test]
    fn signatures_and_tweaks_share_a_batch() {
        let s = sigs(20);
        let t = tweaks(20);
        let run = |s: &[Sig], t: &[Tweak]| {
            let mut batch = Batch::new();
            for (s, t) in s.iter().zip(t) {
                let pk = XOnlyPublicKey::from_bytes(&s.pk).unwrap();
                batch.add_schnorrsig(&s.sig, &s.msg, &pk);
                let internal = XOnlyPublicKey::from_bytes(&t.internal).unwrap();
                batch.add_tweak_check(&t.output, t.odd, &internal, &t.tweak);
            }
            batch.verify()
        };
        assert!(run(&s, &t));
        let mut bad = tweaks(20);
        bad[19].output = bad[18].output;
        assert!(!run(&s, &bad));
    }
}
