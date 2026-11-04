//! Consensus script failures whose numbers match Bitcoin Core v32.1
//! `ScriptError` (`third_party/bitcoin` `f0de87f04062`, `script_error.h`).
//!
//! Policy-only Core codes stay strings at the call site. They are not in
//! this enum, so a proof entry cannot report them as ordinals.

use crate::error::ConsensusError;

/// One consensus `ScriptError` value. Discriminants are Core's, including
/// the holes where a policy code sits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum ScriptFail {
    EvalFalse = 2,
    OpReturn = 3,
    ScriptNum = 4,
    ScriptSize = 5,
    PushSize = 6,
    OpCount = 7,
    StackSize = 8,
    SigCount = 9,
    PubkeyCount = 10,
    Verify = 11,
    EqualVerify = 12,
    CheckMultisigVerify = 13,
    CheckSigVerify = 14,
    NumEqualVerify = 15,
    BadOpcode = 16,
    DisabledOpcode = 17,
    InvalidStackOperation = 18,
    InvalidAltstackOperation = 19,
    UnbalancedConditional = 20,
    NegativeLocktime = 21,
    UnsatisfiedLocktime = 22,
    SigDer = 24,
    SigNullDummy = 28,
    WitnessProgramWrongLength = 38,
    WitnessProgramWitnessEmpty = 39,
    WitnessProgramMismatch = 40,
    WitnessMalleated = 41,
    WitnessMalleatedP2sh = 42,
    WitnessUnexpected = 43,
    SchnorrSigSize = 45,
    SchnorrSigHashType = 46,
    SchnorrSig = 47,
    TaprootWrongControlSize = 48,
    TapscriptValidationWeight = 49,
    TapscriptCheckMultisig = 50,
    TapscriptMinimalIf = 51,
    TapscriptEmptyPubkey = 52,
    OpCodeSeparator = 53,
    SigFindAndDelete = 54,
}

impl ScriptFail {
    pub const fn ordinal(self) -> i32 {
        self as i32
    }

    /// Token already used in [`ConsensusError::Script`] for this failure.
    pub const fn token(self) -> &'static str {
        match self {
            Self::EvalFalse => "EVAL_FALSE",
            Self::OpReturn => "OP_RETURN",
            Self::ScriptNum => "scriptnum",
            Self::ScriptSize => "SCRIPT_SIZE",
            Self::PushSize => "PUSH_SIZE",
            Self::OpCount => "OP_COUNT",
            Self::StackSize => "stack size",
            Self::SigCount => "SIG_COUNT",
            Self::PubkeyCount => "PUBKEY_COUNT",
            Self::Verify => "VERIFY",
            Self::EqualVerify => "OP_EQUALVERIFY",
            Self::CheckMultisigVerify => "CHECKMULTISIGVERIFY",
            Self::CheckSigVerify => "CHECKSIGVERIFY",
            Self::NumEqualVerify => "NUMEQUALVERIFY",
            Self::BadOpcode => "BAD_OPCODE",
            Self::DisabledOpcode => "DISABLED_OPCODE",
            Self::InvalidStackOperation => "stack empty",
            Self::InvalidAltstackOperation => "altstack empty",
            Self::UnbalancedConditional => "UNBALANCED_CONDITIONAL",
            Self::NegativeLocktime => "CLTV negative",
            Self::UnsatisfiedLocktime => "CLTV",
            Self::SigDer => "SIG_DER",
            Self::SigNullDummy => "NULLDUMMY",
            Self::WitnessProgramWrongLength => "WITNESS_PROGRAM_WRONG_LENGTH",
            Self::WitnessProgramWitnessEmpty => "WITNESS_PROGRAM_WITNESS_EMPTY",
            Self::WitnessProgramMismatch => "WITNESS_PROGRAM_MISMATCH",
            Self::WitnessMalleated => "WITNESS_MALLEATED",
            Self::WitnessMalleatedP2sh => "WITNESS_MALLEATED_P2SH",
            Self::WitnessUnexpected => "WITNESS_UNEXPECTED",
            Self::SchnorrSigSize => "SCHNORR_SIG_SIZE",
            Self::SchnorrSigHashType => "SCHNORR_SIG_HASHTYPE",
            Self::SchnorrSig => "SCHNORR_SIG",
            Self::TaprootWrongControlSize => "TAPROOT_WRONG_CONTROL_SIZE",
            Self::TapscriptValidationWeight => "TAPSCRIPT_VALIDATION_WEIGHT",
            Self::TapscriptCheckMultisig => "CHECKMULTISIG disabled in tapscript",
            Self::TapscriptMinimalIf => "TAPSCRIPT_MINIMALIF",
            Self::TapscriptEmptyPubkey => "TAPSCRIPT_EMPTY_PUBKEY",
            Self::OpCodeSeparator => "OP_CODESEPARATOR",
            Self::SigFindAndDelete => "SIG_FINDANDDELETE",
        }
    }
}

impl From<ScriptFail> for ConsensusError {
    fn from(fail: ScriptFail) -> Self {
        ConsensusError::Script(fail.token().to_string())
    }
}

/// Map a shipped script message to a consensus ordinal.
///
/// `txid=` / `vin=` suffixes are ignored. Policy tokens and typed-path
/// strings (`p2wpkh ecdsa`) return `None`.
pub fn consensus_ordinal(message: &str) -> Option<i32> {
    let token = message.split(" txid=").next().unwrap_or(message);
    let fail = match token {
        "EVAL_FALSE" | "script false" => ScriptFail::EvalFalse,
        "OP_RETURN" => ScriptFail::OpReturn,
        "scriptnum" => ScriptFail::ScriptNum,
        "SCRIPT_SIZE" => ScriptFail::ScriptSize,
        "PUSH_SIZE" => ScriptFail::PushSize,
        "OP_COUNT" => ScriptFail::OpCount,
        "stack size" => ScriptFail::StackSize,
        "SIG_COUNT" => ScriptFail::SigCount,
        "PUBKEY_COUNT" => ScriptFail::PubkeyCount,
        "VERIFY" => ScriptFail::Verify,
        "OP_EQUALVERIFY" => ScriptFail::EqualVerify,
        "CHECKMULTISIGVERIFY" => ScriptFail::CheckMultisigVerify,
        "CHECKSIGVERIFY" => ScriptFail::CheckSigVerify,
        "NUMEQUALVERIFY" => ScriptFail::NumEqualVerify,
        "BAD_OPCODE" => ScriptFail::BadOpcode,
        "DISABLED_OPCODE" => ScriptFail::DisabledOpcode,
        "stack empty" => ScriptFail::InvalidStackOperation,
        "altstack empty" => ScriptFail::InvalidAltstackOperation,
        "UNBALANCED_CONDITIONAL" => ScriptFail::UnbalancedConditional,
        "CLTV negative" | "CSV negative" => ScriptFail::NegativeLocktime,
        "CLTV" | "CLTV type" | "CLTV final sequence" | "CSV" | "CSV version" => {
            ScriptFail::UnsatisfiedLocktime
        }
        "SIG_DER" => ScriptFail::SigDer,
        "NULLDUMMY" => ScriptFail::SigNullDummy,
        "WITNESS_PROGRAM_WRONG_LENGTH" => ScriptFail::WitnessProgramWrongLength,
        "WITNESS_PROGRAM_WITNESS_EMPTY" => ScriptFail::WitnessProgramWitnessEmpty,
        "WITNESS_PROGRAM_MISMATCH" => ScriptFail::WitnessProgramMismatch,
        "WITNESS_MALLEATED" => ScriptFail::WitnessMalleated,
        "WITNESS_MALLEATED_P2SH" => ScriptFail::WitnessMalleatedP2sh,
        "WITNESS_UNEXPECTED" => ScriptFail::WitnessUnexpected,
        "SCHNORR_SIG_SIZE" => ScriptFail::SchnorrSigSize,
        "SCHNORR_SIG_HASHTYPE" | "tapscript sighash" => ScriptFail::SchnorrSigHashType,
        "SCHNORR_SIG" | "p2tr schnorr" | "tapscript CHECKSIG failed" => ScriptFail::SchnorrSig,
        "TAPROOT_WRONG_CONTROL_SIZE" => ScriptFail::TaprootWrongControlSize,
        "TAPSCRIPT_VALIDATION_WEIGHT" | "tapscript validation weight" => {
            ScriptFail::TapscriptValidationWeight
        }
        "CHECKMULTISIG disabled in tapscript" | "CHECKMULTISIGVERIFY disabled in tapscript" => {
            ScriptFail::TapscriptCheckMultisig
        }
        "TAPSCRIPT_MINIMALIF" => ScriptFail::TapscriptMinimalIf,
        "TAPSCRIPT_EMPTY_PUBKEY" | "tapscript empty pubkey" => ScriptFail::TapscriptEmptyPubkey,
        "OP_CODESEPARATOR" => ScriptFail::OpCodeSeparator,
        "SIG_FINDANDDELETE" => ScriptFail::SigFindAndDelete,
        _ => return None,
    };
    Some(fail.ordinal())
}
