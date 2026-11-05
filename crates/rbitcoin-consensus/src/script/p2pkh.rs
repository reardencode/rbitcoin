//! Native P2PKH verification (legacy).

use std::borrow::Cow;

use bitcoin::hashes::Hash;
use bitcoin::script::{Instruction, Script};
use bitcoin::sighash::SighashCache;
use bitcoin::Transaction;

use super::{crypto, interpreter};
use crate::block::ScriptCheckJob;
use crate::error::ConsensusError;

pub fn verify(
    job: &ScriptCheckJob,
    input_index: crate::block::InputIndex,
    tx: &Transaction,
    cache: &mut SighashCache<&Transaction>,
) -> Result<(), ConsensusError> {
    let _ = tx;
    let spk = job.prevout_script(input_index)?;
    debug_assert!(spk.len() == 25);
    let keyhash = &spk[3..23];

    let input = &tx.input[input_index.get()];
    let (sig_raw, pubkey_raw) = parse_two_pushes(input.script_sig.as_script())?;

    let pk_hash = crypto::hash160(&pubkey_raw);
    if pk_hash.as_slice() != keyhash {
        return Err(ConsensusError::Script("p2pkh pubkey hash".into()));
    }

    let (sig, sighash_ty) = crypto::parse_der_sig(&sig_raw, job.bip66_active)?;
    let pubkey = crypto::parse_pubkey(&pubkey_raw)?;

    let script_code_bytes = sighash_script_code(spk, &sig_raw);
    let script_code = Script::from_bytes(&script_code_bytes);
    // Raw hashtype byte (may be 0 — must not normalize to SIGHASH_ALL).
    let sighash = cache
        .legacy_signature_hash(input_index.get(), script_code, sighash_ty)
        .map_err(|_| ConsensusError::Script("p2pkh sighash".into()))?;
    if crypto::verify_ecdsa(sighash.to_byte_array(), &sig, &pubkey) {
        Ok(())
    } else {
        Err(ConsensusError::Script("p2pkh ecdsa".into()))
    }
}

#[doc(hidden)]
pub fn parse_two_pushes(script: &Script) -> Result<(Vec<u8>, Vec<u8>), ConsensusError> {
    let mut items = Vec::with_capacity(2);
    for ins in script.instructions() {
        match ins.map_err(|_| ConsensusError::Script("p2pkh scriptSig".into()))? {
            // Over-size pushes are a shape error so the interpreter reports
            // PUSH_SIZE. Two pushes of at most 520 bytes keep the scriptSig
            // far below MAX_SCRIPT_SIZE.
            Instruction::PushBytes(b) if b.len() > interpreter::MAX_SCRIPT_ELEMENT_SIZE => {
                return Err(ConsensusError::Script("p2pkh scriptSig".into()));
            }
            Instruction::PushBytes(b) => items.push(b.as_bytes().to_vec()),
            // OP_1..=OP_16 and every other opcode are the same shape error.
            Instruction::Op(_) => {
                return Err(ConsensusError::Script(
                    "p2pkh scriptSig unexpected op".into(),
                ));
            }
        }
    }
    if items.len() != 2 {
        return Err(ConsensusError::Script("p2pkh scriptSig len".into()));
    }
    Ok((items[0].clone(), items[1].clone()))
}

/// ScriptCode left after `FindAndDelete` on the P2PKH template.
///
/// `is_p2pkh` is `OP_DUP OP_HASH160 PUSH20 <keyhash> OP_EQUALVERIFY OP_CHECKSIG`.
/// The signature push matches an instruction boundary only when it is those
/// 20 keyhash bytes. The template has no bare `OP_CODESEPARATOR`. Any other
/// signature hashes `spk` unchanged, with no script walk and no allocation.
fn sighash_script_code<'a>(spk: &'a [u8], sig: &[u8]) -> Cow<'a, [u8]> {
    if spk.len() == 25 && sig.len() == 20 && sig == &spk[3..23] {
        Cow::Borrowed(P2PKH_SCRIPT_CODE_KEYHASH_REMOVED)
    } else {
        Cow::Borrowed(spk)
    }
}

/// `OP_DUP OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG`.
const P2PKH_SCRIPT_CODE_KEYHASH_REMOVED: &[u8] = &[0x76, 0xa9, 0x88, 0xac];

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::PublicKey;

    #[test]
    fn keyhash_collision_script_code_is_the_deleted_template() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[9u8; 32]).unwrap();
        let pk = PublicKey::new(sk.public_key(&secp));
        let spk = bitcoin::ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::hash(&pk.to_bytes()));
        let keyhash = bitcoin::PubkeyHash::hash(&pk.to_bytes());
        let code = super::sighash_script_code(spk.as_bytes(), keyhash.as_byte_array());
        // OP_DUP OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG. The 20-byte push is gone.
        // Borrowed: the fast path must not allocate a scriptCode for this hit.
        assert!(matches!(code, std::borrow::Cow::Borrowed(_)));
        assert_eq!(code.as_ref(), &[0x76, 0xa9, 0x88, 0xac]);
        assert_ne!(code.as_ref(), spk.as_bytes());
    }

    #[test]
    fn other_signatures_hash_the_template_in_place() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[9u8; 32]).unwrap();
        let pk = PublicKey::new(sk.public_key(&secp));
        let spk = bitcoin::ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::hash(&pk.to_bytes()));
        let raw = spk.as_bytes();
        let ordinary = [0x30u8; 71];
        let same = super::sighash_script_code(raw, &ordinary);
        assert!(matches!(same, std::borrow::Cow::Borrowed(_)));
        assert!(std::ptr::eq(same.as_ref(), raw));
        let mut miss = [0u8; 20];
        miss[0] = 0x30;
        let untouched = super::sighash_script_code(raw, &miss);
        assert!(std::ptr::eq(untouched.as_ref(), raw));
    }
}
