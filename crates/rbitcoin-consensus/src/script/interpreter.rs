//! Bitcoin Script stack interpreter for P2WSH / P2SH / bare / tapscript.
//!
//! **Goal:** implement *all* consensus-enabled opcodes so IBD does not fail
//! post-milestone on the next rarely-used opcode. Whack-a-mole is not a strategy.
//!
//! Opcode semantics are **sigversion-aware**:
//! - Legacy / Witness v0: 10 000-byte script limit, 201 non-push ops; disabled
//!   opcodes (CAT, …) fail if executed; RESERVED/VER fail if executed.
//! - Tapscript (BIP342): no script-size or op-count limit; OP_SUCCESSx anywhere
//!   → unconditional success; CHECKMULTISIG disabled; MINIMALIF consensus;
//!   CHECKSIGADD; empty-pubkey / unknown-key-type / hard-fail-on-bad-sig rules.
//!
//! This module implements **consensus** checks only. Relay / standardness lives
//! in [`crate::policy`] and must never reject blocks.

use std::borrow::Cow;
use std::cell::{Cell, RefCell};

use bitcoin::hashes::Hash;
use bitcoin::script::{Instruction, Script};
use bitcoin::sighash::SighashCache;
use bitcoin::{Amount, Sequence, Transaction};

use super::crypto;
use crate::error::ConsensusError;
use rbitcoin_primitives::script_opcode::{
    OP_1NEGATE, OP_2DIV, OP_2MUL, OP_AND, OP_CAT, OP_CODESEPARATOR, OP_DIV, OP_INVERT, OP_LEFT,
    OP_LSHIFT, OP_MOD, OP_MUL, OP_OR, OP_PUSHBYTES_75, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4,
    OP_RESERVED, OP_RIGHT, OP_RSHIFT, OP_SUBSTR, OP_VERIF, OP_VERNOTIF, OP_XOR,
};
use rbitcoin_primitives::{scriptnum_decode_width, scriptnum_encode};

/// Stack element cap (main + alt).
pub const MAX_STACK_SIZE: usize = 1000;
/// Push / witness stack item cap.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Bytes a script push or witness element may hold.
///
/// The parser rejects a longer push before this value exists. `find_and_delete`
/// and `check_minimal_push` take it so a 65_536-byte needle cannot be built.
#[derive(Clone, Copy)]
pub struct ScriptElem<'a>(&'a [u8]);

impl<'a> ScriptElem<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, ConsensusError> {
        if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ConsensusError::Script("push too large".into()));
        }
        Ok(Self(data))
    }

    #[inline]
    pub fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}
/// BIP342 `VALIDATION_WEIGHT_OFFSET` / `VALIDATION_WEIGHT_PER_SIGOP_PASSED`.
#[doc(hidden)]
pub const TAPSCRIPT_VALIDATION_WEIGHT_OFFSET: i64 = 50;
#[doc(hidden)]
pub const TAPSCRIPT_VALIDATION_WEIGHT_PER_SIGOP: i64 = 50;

/// Legacy / witness-v0 script size cap (BIP16 / BIP141). **Not** applied in tapscript
/// (BIP342: size only bounded by block weight).
#[doc(hidden)]
pub const MAX_SCRIPT_SIZE_LEGACY: usize = 10_000;
/// Legacy / witness-v0 non-push opcode budget. **Not** applied in tapscript (BIP342).
#[doc(hidden)]
pub const MAX_OPS_LEGACY: usize = 201;
#[doc(hidden)]
pub const MAX_PUBKEYS_PER_MULTISIG: i64 = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigVersion {
    Base,
    WitnessV0,
    TapScript,
}

/// ECDSA CHECKSIG / CHECKMULTISIG. TapScript is routed before this path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PreTapscript {
    Base,
    WitnessV0,
}

impl PreTapscript {
    #[doc(hidden)]
    pub fn from_sig_version(version: SigVersion) -> Option<Self> {
        match version {
            SigVersion::Base => Some(Self::Base),
            SigVersion::WitnessV0 => Some(Self::WitnessV0),
            SigVersion::TapScript => None,
        }
    }
}

/// BIP342 OP_SUCCESSx opcode numbers (decimal).
///
/// If any of these appears in a **tapscript** during decoding, the script is
/// unconditionally valid.
/// Classic disabled opcodes (legacy / witness v0) — consensus fail if executed.
#[doc(hidden)]
pub fn is_disabled_legacy(code: u8) -> bool {
    matches!(
        code,
        OP_CAT
            | OP_SUBSTR
            | OP_LEFT
            | OP_RIGHT
            | OP_INVERT
            | OP_AND
            | OP_OR
            | OP_XOR
            | OP_2MUL
            | OP_2DIV
            | OP_MUL
            | OP_DIV
            | OP_MOD
            | OP_LSHIFT
            | OP_RSHIFT
    )
}

#[doc(hidden)]
pub fn is_op_success(code: u8) -> bool {
    matches!(
        code,
        80 | 98
            | 126
            | 127
            | 128
            | 129
            | 131
            | 132
            | 133
            | 134
            | 137
            | 138
            | 141
            | 142
            | 149
            | 150
            | 151
            | 152
            | 153
    ) || (187..=254).contains(&code)
}

/// BIP342: scan tapscript for OP_SUCCESSx. Returns true if the script is valid
/// before resource limits. This stays a separate walk: an `OP_SUCCESS` after a
/// prefix that would blow a limit is still valid, and those limits must not run.
pub fn tapscript_has_op_success(script: &Script) -> bool {
    let bytes = script.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let op = bytes[i];
        if (1..=OP_PUSHBYTES_75).contains(&op) {
            let n = op as usize;
            i = i.saturating_add(1).saturating_add(n);
            continue;
        }
        match op {
            OP_PUSHDATA1 => {
                if i + 1 >= bytes.len() {
                    break;
                }
                let n = bytes[i + 1] as usize;
                i = i.saturating_add(2).saturating_add(n);
            }
            OP_PUSHDATA2 => {
                if i + 2 >= bytes.len() {
                    break;
                }
                let n = u16::from_le_bytes([bytes[i + 1], bytes[i + 2]]) as usize;
                i = i.saturating_add(3).saturating_add(n);
            }
            OP_PUSHDATA4 => {
                if i + 4 >= bytes.len() {
                    break;
                }
                let n = u32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]])
                    as usize;
                i = i.saturating_add(5).saturating_add(n);
            }
            _ => {
                if is_op_success(op) {
                    return true;
                }
                i += 1;
            }
        }
    }
    false
}

pub struct EvalContext<'a> {
    pub tx: &'a Transaction,
    pub input_index: crate::block::InputIndex,
    pub amount: Amount,
    /// scriptCode for sighash (redeem / witness script).
    pub script_code: &'a Script,
    pub sig_version: SigVersion,
    /// When false, OP_CLTV (0xb1) is a no-op (pre-BIP65).
    pub bip65_active: bool,
    /// When false, OP_CSV (0xb2) is a no-op (pre-BIP112).
    pub bip112_active: bool,
    /// When true, ECDSA signatures must be strict DER (BIP66 / SCRIPT_VERIFY_DERSIG).
    pub bip66_active: bool,
    /// Minimal push opcodes + minimal script integers.
    /// Not always consensus (standard flag); enabled when fixture/job requests it.
    pub minimal_data: bool,
    /// Non-empty sig that fails CHECK(MULTI)SIG → hard fail.
    pub nullfail: bool,
    /// High-S ECDSA signatures hard-fail (standardness).
    pub low_s: bool,
    /// DER + defined hashtype + compressed/uncompressed keys.
    pub strictenc: bool,
    /// BIP147: CMS dummy must be empty.
    pub null_dummy: bool,
    /// IF/NOTIF argument must be empty or exact 0x01.
    /// Always on for TapScript; optional flag for legacy/v0.
    pub minimal_if: bool,
    /// Only compressed keys in witness scripts.
    pub witness_pubkeytype: bool,
    /// Reject CODESEPARATOR / FindAndDelete that would mutate scriptCode.
    pub const_scriptcode: bool,
    /// BIP342: instruction index of last executed OP_CODESEPARATOR, or `0xFFFFFFFF`.
    ///
    /// Counted one per instruction, not byte offset.
    pub codeseparator_pos: Cell<u32>,
    /// Base / WitnessV0: byte offset into `script_code` of the first opcode **after**
    /// the last executed OP_CODESEPARATOR. `None` = full script.
    ///
    /// BIP143 / legacy CHECKSIG use this truncated script as `scriptCode`.
    pub codeseparator_script_off: Cell<Option<usize>>,
    /// Legacy midstate. Created on first use (WitnessV0 uses `pre`, tapscript `tapscript`).
    pub cache: RefCell<Option<SighashCache<&'a Transaction>>>,
    /// Structure/lookup midstates (WitnessV0 BIP143).
    pub pre: Cow<'a, crate::TxScriptPrecompute>,
    /// BIP342 remaining validation weight (`50 + witness serialized size`).
    pub validation_weight_left: Cell<i64>,
    /// Tapscript only: per-input sighash facts from the script-path spend.
    pub tapscript: Option<crypto::TapscriptExecData<'a>>,
}

/// Placeholder row for a base sighash. Legacy `CHECKSIG` hashes through
/// `SighashCache` and does not read these midstates. A witness spend never
/// borrows this row.
#[doc(hidden)]
pub fn base_sig_precompute() -> &'static crate::TxScriptPrecompute {
    use std::sync::OnceLock;
    static ROW: OnceLock<crate::TxScriptPrecompute> = OnceLock::new();
    ROW.get_or_init(|| crate::TxScriptPrecompute {
        connect: crate::TxConnectPrecompute {
            txid: [0; 32],
            wtxid: [0; 32],
            base_size: 0,
            total_size: 0,
            sigops: 0,
            out_sum: 0,
            has_witness: false,
        },
        sha_prevouts: [0; 32],
        sha_sequences: [0; 32],
        sha_outputs: [0; 32],
        sha_amounts: None,
        sha_scriptpubkeys: None,
        prevouts_d: OnceLock::new(),
        sequences_d: OnceLock::new(),
        outputs_d: OnceLock::new(),
    })
}

impl<'a> EvalContext<'a> {
    #[cfg(debug_assertions)]
    pub fn new(
        tx: &'a Transaction,
        input_index: usize,
        amount: Amount,
        script_code: &'a Script,
        sig_version: SigVersion,
    ) -> Self {
        Self::new_with_flags(
            tx,
            input_index,
            amount,
            script_code,
            sig_version,
            true,
            true,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)] // call-site args stay unbundled
    #[cfg(debug_assertions)]
    pub fn new_with_flags(
        tx: &'a Transaction,
        input_index: usize,
        amount: Amount,
        script_code: &'a Script,
        sig_version: SigVersion,
        bip65_active: bool,
        bip112_active: bool,
        bip66_active: bool,
    ) -> Self {
        Self::from_eval_parts(
            tx,
            input_index,
            amount,
            script_code,
            sig_version,
            bip65_active,
            bip112_active,
            bip66_active,
            Cow::Owned(crate::TxScriptPrecompute::from_tx(tx)),
        )
        .expect("input index")
    }

    #[allow(clippy::too_many_arguments)] // call-site args stay unbundled
    #[doc(hidden)]
    pub fn from_eval_parts(
        tx: &'a Transaction,
        input_index: usize,
        amount: Amount,
        script_code: &'a Script,
        sig_version: SigVersion,
        bip65_active: bool,
        bip112_active: bool,
        bip66_active: bool,
        pre: Cow<'a, crate::TxScriptPrecompute>,
    ) -> Result<Self, ConsensusError> {
        let input_index = crate::block::InputIndex::in_tx(tx, input_index)?;
        Ok(Self {
            tx,
            input_index,
            amount,
            script_code,
            sig_version,
            bip65_active,
            bip112_active,
            bip66_active,
            minimal_data: false,
            nullfail: false,
            low_s: false,
            strictenc: false,
            null_dummy: false,
            minimal_if: false,
            witness_pubkeytype: false,
            const_scriptcode: false,
            codeseparator_pos: Cell::new(0xFFFF_FFFF),
            codeseparator_script_off: Cell::new(None),
            cache: RefCell::new(None),
            pre,
            validation_weight_left: Cell::new(tapscript_init_weight(
                tx,
                input_index.get(),
                sig_version,
            )),
            tapscript: None,
        })
    }

    /// Attach the tapleaf and annex facts of a BIP341 script-path spend.
    pub fn with_tapscript(mut self, exec: crypto::TapscriptExecData<'a>) -> Self {
        self.tapscript = Some(exec);
        self
    }

    /// Copy standardness / fixture flags from a [`crate::block::ScriptCheckJob`].
    pub fn apply_job_flags(mut self, job: &crate::block::ScriptCheckJob) -> Self {
        self.minimal_data = job.minimal_data;
        self.nullfail = job.nullfail;
        self.low_s = job.low_s;
        self.strictenc = job.strictenc;
        self.null_dummy = job.null_dummy;
        self.minimal_if = job.minimal_if;
        self.witness_pubkeytype = job.witness_pubkeytype;
        self.const_scriptcode = job.const_scriptcode;
        if job.low_s || job.strictenc {
            self.bip66_active = true;
        }
        self
    }

    /// Build an eval context from a script job: activation + standardness flags in one place.
    ///
    /// Prefer this over `new_with_flags(...).apply_job_flags(job)` at production call sites
    /// so flag wiring cannot drift between typed paths.
    #[inline]
    pub fn from_job(
        job: &'a crate::block::ScriptCheckJob,
        tx: &'a Transaction,
        input_index: crate::block::InputIndex,
        script_code: &'a Script,
        sig_version: SigVersion,
    ) -> Result<Self, ConsensusError> {
        let amount = job.prevout_amount(input_index)?;
        let pre = if sig_version == SigVersion::Base {
            Cow::Borrowed(base_sig_precompute())
        } else {
            Cow::Borrowed(job.pre()?)
        };
        Ok(Self::from_eval_parts(
            tx,
            input_index.get(),
            amount,
            script_code,
            sig_version,
            job.bip65_active,
            job.bip112_active,
            job.bip66_active,
            pre,
        )?
        .apply_job_flags(job))
    }
}

/// BIP141 / BIP342: exactly one true value on the stack (witness / tapscript).
pub fn require_clean_true(stack: &[Vec<u8>]) -> Result<(), ConsensusError> {
    if stack.len() != 1 {
        return Err(ConsensusError::Script("cleanstack".into()));
    }
    if !bitcoin::script::read_scriptbool(&stack[0]) {
        return Err(ConsensusError::Script("script false".into()));
    }
    Ok(())
}

/// BIP16 / legacy: final stack must be non-empty with a true top element.
///
/// **Not** cleanstack — BIP62 CLEANSTACK was never activated for non-witness
/// consensus. Requiring `len==1` falsely rejected valid P2SH (signet 219477).
pub fn require_true_top(stack: &[Vec<u8>]) -> Result<(), ConsensusError> {
    if stack.is_empty() || !bitcoin::script::read_scriptbool(stack.last().unwrap()) {
        return Err(ConsensusError::Script("script false".into()));
    }
    Ok(())
}

/// Evaluate scriptSig as push-only onto `stack` (BIP16 P2SH / SIGPUSHONLY).
///
/// **Not** used for bare script verification — historical bare spends may run
/// non-push opcodes in scriptSig (e.g. `OP_CODESEPARATOR` + `CHECKMULTISIG` at
/// mainnet height 163685). Callers that need BIP16 push-only must use this
/// helper; bare paths use full [`eval_script`] on scriptSig.
#[cfg(debug_assertions)]
pub fn eval_script_sig_pushes(
    script: &Script,
    stack: &mut Vec<Vec<u8>>,
) -> Result<(), ConsensusError> {
    for ins in script.instructions() {
        match ins.map_err(|_| ConsensusError::Script("scriptSig parse".into()))? {
            Instruction::PushBytes(b) => {
                push(stack, 0, b.as_bytes().to_vec())?;
            }
            Instruction::Op(op) => {
                let n = op.to_u8();
                if n == 0x00 {
                    push(stack, 0, vec![])?;
                } else if n == 0x4f {
                    push(stack, 0, vec![0x81])?;
                } else if (0x51..=0x60).contains(&n) {
                    push(stack, 0, vec![n - 0x50])?;
                } else {
                    return Err(ConsensusError::Script("scriptSig non-push".into()));
                }
            }
        }
    }
    Ok(())
}

/// Core `ConditionStack`: IF/NOTIF/ELSE nesting as a depth plus the index of
/// the first false entry, so the per-opcode "executing" check is O(1).
///
/// Tapscript has no opcode limit; a `Vec<bool>` scanned on every opcode is
/// quadratic in nesting depth. Toggling an entry above the first false one
/// is unobservable, so only that index is tracked.
#[derive(Default)]
#[doc(hidden)]
pub struct ConditionStack {
    pub size: usize,
    pub first_false: Option<usize>,
}

impl ConditionStack {
    #[doc(hidden)]
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    #[doc(hidden)]
    pub fn all_true(&self) -> bool {
        self.first_false.is_none()
    }

    #[doc(hidden)]
    pub fn push(&mut self, value: bool) {
        if self.first_false.is_none() && !value {
            self.first_false = Some(self.size);
        }
        self.size += 1;
    }

    /// Caller checks [`Self::is_empty`] first (`OP_ENDIF` without `OP_IF`).
    #[doc(hidden)]
    pub fn pop(&mut self) {
        self.size -= 1;
        if self.first_false == Some(self.size) {
            self.first_false = None;
        }
    }

    /// Caller checks [`Self::is_empty`] first (`OP_ELSE` without `OP_IF`).
    #[doc(hidden)]
    pub fn toggle_top(&mut self) {
        let top = self.size - 1;
        match self.first_false {
            None => self.first_false = Some(top),
            Some(pos) if pos == top => self.first_false = None,
            Some(_) => {}
        }
    }
}

/// Evaluate `script`. On success returns `true` if cleanstack must still be
/// checked; `false` if the script already fully succeeded (e.g. OP_SUCCESS).
pub fn eval_script(
    script: &Script,
    stack: &mut Vec<Vec<u8>>,
    ctx: &EvalContext<'_>,
) -> Result<bool, ConsensusError> {
    let bytes = script.as_bytes();
    // BIP342: OP_SUCCESSx anywhere in tapscript → unconditional success *before*
    // size / stack limits (even unparseable tails pass).
    if ctx.sig_version == SigVersion::TapScript && tapscript_has_op_success(script) {
        return Ok(false);
    }
    if ctx.sig_version == SigVersion::TapScript {
        if stack.len() > MAX_STACK_SIZE {
            return Err(ConsensusError::Script("stack size".into()));
        }
        for item in stack.iter() {
            if item.len() > MAX_SCRIPT_ELEMENT_SIZE {
                return Err(ConsensusError::Script("PUSH_SIZE".into()));
            }
        }
    }
    // Legacy / v0 only: 10k script size. Tapscript: no explicit size limit.
    if ctx.sig_version != SigVersion::TapScript && bytes.len() > MAX_SCRIPT_SIZE_LEGACY {
        return Err(ConsensusError::Script("script too large".into()));
    }

    let mut altstack: Vec<Vec<u8>> = Vec::new();
    let mut cond_stack = ConditionStack::default();
    let mut op_count = 0usize;
    let enforce_op_limit = ctx.sig_version != SigVersion::TapScript;
    // TapScript always MINIMALIF. SCRIPT_VERIFY_MINIMALIF applies to witness v0
    // (and tapscript); bare/Base scripts ignore the flag (Core fixture #1197).
    let minimal_if = ctx.sig_version == SigVersion::TapScript
        || (ctx.minimal_if && ctx.sig_version == SigVersion::WitnessV0);
    // BIP342 / Core: instruction index for codeseparator_pos (not byte offset).
    let mut opcode_pos: u32 = 0;
    // Prefer instruction_indices so OP_CODESEPARATOR can set Base/WitnessV0
    // scriptCode byte offsets (BIP143 / Core pbegincodehash).
    for item in script.instruction_indices() {
        let (byte_index, ins) = item.map_err(|_| ConsensusError::Script("script parse".into()))?;
        let this_pos = opcode_pos;
        opcode_pos = opcode_pos.saturating_add(1);
        let executing = cond_stack.all_true();

        match ins {
            Instruction::PushBytes(b) => {
                // Core: MAX_SCRIPT_ELEMENT_SIZE even in unexecuted branches.
                let data = b.as_bytes();
                let elem = ScriptElem::new(data)?;
                // Core MINIMALDATA: CheckMinimalPush only when the push executes
                // (unexecuted IF branches ignore non-minimal encodings).
                if executing {
                    if ctx.minimal_data {
                        let opcode = bytes.get(byte_index).copied().unwrap_or(0);
                        if !check_minimal_push(elem, opcode) {
                            return Err(ConsensusError::Script("MINIMALDATA".into()));
                        }
                    }
                    push(stack, altstack.len(), data.to_vec())?;
                }
            }
            Instruction::Op(op) => {
                let code = op.to_u8();

                // Legacy / v0: opcodes > OP_16 count toward 201 even when skipped,
                // including OP_IF / NOTIF / ELSE / ENDIF.
                if enforce_op_limit && code > 0x60 {
                    op_count += 1;
                    if op_count > MAX_OPS_LEGACY {
                        return Err(ConsensusError::Script("op count".into()));
                    }
                }

                // IF/ELSE/ENDIF must run even when skipped (structure, not value).
                match code {
                    0x63 => {
                        let mut cond = false;
                        if executing {
                            let v = pop(stack)?;
                            if minimal_if && !is_minimal_if_arg(&v) {
                                return Err(ConsensusError::Script("MINIMALIF".into()));
                            }
                            cond = bitcoin::script::read_scriptbool(&v);
                        }
                        cond_stack.push(executing && cond);
                        continue;
                    }
                    0x64 => {
                        let mut cond = false;
                        if executing {
                            let v = pop(stack)?;
                            if minimal_if && !is_minimal_if_arg(&v) {
                                return Err(ConsensusError::Script("MINIMALIF".into()));
                            }
                            cond = !bitcoin::script::read_scriptbool(&v);
                        }
                        cond_stack.push(executing && cond);
                        continue;
                    }
                    0x67 => {
                        if cond_stack.is_empty() {
                            return Err(ConsensusError::Script("OP_ELSE".into()));
                        }
                        cond_stack.toggle_top();
                        continue;
                    }
                    0x68 => {
                        if cond_stack.is_empty() {
                            return Err(ConsensusError::Script("OP_ENDIF".into()));
                        }
                        cond_stack.pop();
                        continue;
                    }
                    _ => {}
                }

                // Core: OP_VERIF / OP_VERNOTIF always fail (even unexecuted).
                if code == OP_VERIF || code == OP_VERNOTIF {
                    return Err(ConsensusError::Script("OP_VERIF".into()));
                }
                // Core: disabled opcodes fail even in unexecuted branches (legacy/v0).
                if ctx.sig_version != SigVersion::TapScript && is_disabled_legacy(code) {
                    return Err(ConsensusError::Script(format!(
                        "disabled opcode 0x{code:02x}"
                    )));
                }
                // CONST_SCRIPTCODE: OP_CODESEPARATOR rejected in Base even unexecuted.
                if code == OP_CODESEPARATOR
                    && ctx.const_scriptcode
                    && ctx.sig_version == SigVersion::Base
                {
                    return Err(ConsensusError::Script("OP_CODESEPARATOR".into()));
                }

                if !executing {
                    continue;
                }

                let rm = ctx.minimal_data;
                // `push` enforces the shared stack limit. Every growth goes
                // through `push`, and OP_TOALTSTACK only moves an element. A
                // witness v0 stack can start above the limit, so a pop and a
                // push can still fail.
                match code {
                    // OP_0 is PushBytes, not an opcode. OP_RESERVED, OP_VER,
                    // OP_VERIF, and OP_RETURN fail from the unknown-opcode arm
                    // (OP_VERIF already returned above, including unexecuted).
                    0x4f => push(stack, altstack.len(), vec![0x81])?,
                    n if (0x51..=0x60).contains(&n) => push(stack, altstack.len(), vec![n - 0x50])?,
                    0x61 => {}
                    0x69 => {
                        let v = pop(stack)?;
                        if !bitcoin::script::read_scriptbool(&v) {
                            return Err(ConsensusError::Script("OP_VERIFY".into()));
                        }
                    }

                    0x6b => {
                        let v = pop(stack)?;
                        altstack.push(v);
                    }
                    0x6c => {
                        let v = altstack
                            .pop()
                            .ok_or_else(|| ConsensusError::Script("altstack empty".into()))?;
                        push(stack, altstack.len(), v)?;
                    }
                    0x6d => {
                        pop(stack)?;
                        pop(stack)?;
                    }
                    0x6e => {
                        require_n(stack, 2)?;
                        let a = stack[stack.len() - 2].clone();
                        let b = stack[stack.len() - 1].clone();
                        push(stack, altstack.len(), a)?;
                        push(stack, altstack.len(), b)?;
                    }
                    0x6f => {
                        require_n(stack, 3)?;
                        let a = stack[stack.len() - 3].clone();
                        let b = stack[stack.len() - 2].clone();
                        let c = stack[stack.len() - 1].clone();
                        push(stack, altstack.len(), a)?;
                        push(stack, altstack.len(), b)?;
                        push(stack, altstack.len(), c)?;
                    }
                    0x70 => {
                        require_n(stack, 4)?;
                        let a = stack[stack.len() - 4].clone();
                        let b = stack[stack.len() - 3].clone();
                        push(stack, altstack.len(), a)?;
                        push(stack, altstack.len(), b)?;
                    }
                    0x71 => {
                        require_n(stack, 6)?;
                        let n = stack.len();
                        let x1 = stack[n - 6].clone();
                        let x2 = stack[n - 5].clone();
                        for i in 0..4 {
                            stack[n - 6 + i] = stack[n - 4 + i].clone();
                        }
                        stack[n - 2] = x1;
                        stack[n - 1] = x2;
                    }
                    0x72 => {
                        require_n(stack, 4)?;
                        let n = stack.len();
                        stack.swap(n - 4, n - 2);
                        stack.swap(n - 3, n - 1);
                    }
                    0x73 => {
                        require_n(stack, 1)?;
                        if bitcoin::script::read_scriptbool(stack.last().unwrap()) {
                            let v = stack.last().unwrap().clone();
                            push(stack, altstack.len(), v)?;
                        }
                    }
                    0x74 => {
                        let d = stack.len() as i64;
                        push(stack, altstack.len(), scriptnum_encode(d))?;
                    }
                    0x75 => {
                        pop(stack)?;
                    }
                    0x76 => {
                        require_n(stack, 1)?;
                        let v = stack.last().unwrap().clone();
                        push(stack, altstack.len(), v)?;
                    }
                    0x77 => {
                        require_n(stack, 2)?;
                        let top = pop(stack)?;
                        pop(stack)?;
                        push(stack, altstack.len(), top)?;
                    }
                    0x78 => {
                        require_n(stack, 2)?;
                        let v = stack[stack.len() - 2].clone();
                        push(stack, altstack.len(), v)?;
                    }
                    0x79 => {
                        let n = decode_i64(&pop(stack)?, rm)?;
                        if n < 0 || n as usize >= stack.len() {
                            return Err(ConsensusError::Script("OP_PICK".into()));
                        }
                        let v = stack[stack.len() - 1 - n as usize].clone();
                        push(stack, altstack.len(), v)?;
                    }
                    0x7a => {
                        let n = decode_i64(&pop(stack)?, rm)?;
                        if n < 0 || n as usize >= stack.len() {
                            return Err(ConsensusError::Script("OP_ROLL".into()));
                        }
                        let idx = stack.len() - 1 - n as usize;
                        let v = stack.remove(idx);
                        push(stack, altstack.len(), v)?;
                    }
                    0x7b => {
                        require_n(stack, 3)?;
                        let n = stack.len();
                        stack.swap(n - 3, n - 2);
                        stack.swap(n - 2, n - 1);
                    }
                    0x7c => {
                        require_n(stack, 2)?;
                        let n = stack.len();
                        stack.swap(n - 1, n - 2);
                    }
                    0x7d => {
                        require_n(stack, 2)?;
                        let v = stack[stack.len() - 1].clone();
                        push(stack, altstack.len(), v)?;
                        let n = stack.len();
                        stack.swap(n - 3, n - 2);
                    }
                    0x82 => {
                        require_n(stack, 1)?;
                        let sz = stack.last().unwrap().len() as i64;
                        push(stack, altstack.len(), scriptnum_encode(sz))?;
                    }
                    0x87 => {
                        let a = pop(stack)?;
                        let b = pop(stack)?;
                        push(stack, altstack.len(), bool_encode(a == b))?;
                    }
                    0x88 => {
                        let a = pop(stack)?;
                        let b = pop(stack)?;
                        if a != b {
                            return Err(ConsensusError::Script("OP_EQUALVERIFY".into()));
                        }
                    }
                    0x8b => {
                        let v = decode_i64(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), scriptnum_encode(v.saturating_add(1)))?;
                    }
                    0x8c => {
                        let v = decode_i64(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), scriptnum_encode(v.saturating_sub(1)))?;
                    }
                    0x8f => {
                        let v = decode_i64(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), scriptnum_encode(-v))?;
                    }
                    0x90 => {
                        let v = decode_i64(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), scriptnum_encode(v.abs()))?;
                    }
                    0x91 => {
                        let v = decode_i64(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), bool_encode(v == 0))?;
                    }
                    0x92 => {
                        let v = decode_i64(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), bool_encode(v != 0))?;
                    }
                    0x93 => bin_arith(stack, altstack.len(), rm, |a, b| a + b)?,
                    0x94 => bin_arith(stack, altstack.len(), rm, |a, b| a - b)?,
                    0x9a => {
                        let b = decode_i64(&pop(stack)?, rm)?;
                        let a = decode_i64(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), bool_encode(a != 0 && b != 0))?;
                    }
                    0x9b => {
                        let b = decode_i64(&pop(stack)?, rm)?;
                        let a = decode_i64(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), bool_encode(a != 0 || b != 0))?;
                    }
                    0x9c => bin_cmp(stack, altstack.len(), rm, |a, b| a == b)?,
                    0x9d => {
                        let b = decode_i64(&pop(stack)?, rm)?;
                        let a = decode_i64(&pop(stack)?, rm)?;
                        if a != b {
                            return Err(ConsensusError::Script("OP_NUMEQUALVERIFY".into()));
                        }
                    }
                    0x9e => bin_cmp(stack, altstack.len(), rm, |a, b| a != b)?,
                    0x9f => bin_cmp(stack, altstack.len(), rm, |a, b| a < b)?,
                    0xa0 => bin_cmp(stack, altstack.len(), rm, |a, b| a > b)?,
                    0xa1 => bin_cmp(stack, altstack.len(), rm, |a, b| a <= b)?,
                    0xa2 => bin_cmp(stack, altstack.len(), rm, |a, b| a >= b)?,
                    0xa3 => {
                        let b = decode_i64(&pop(stack)?, rm)?;
                        let a = decode_i64(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), scriptnum_encode(a.min(b)))?;
                    }
                    0xa4 => {
                        let b = decode_i64(&pop(stack)?, rm)?;
                        let a = decode_i64(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), scriptnum_encode(a.max(b)))?;
                    }
                    0xa5 => {
                        let max = decode_i64(&pop(stack)?, rm)?;
                        let min = decode_i64(&pop(stack)?, rm)?;
                        let x = decode_i64(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), bool_encode(x >= min && x < max))?;
                    }
                    0xa6 => {
                        let v = pop(stack)?;
                        use bitcoin::hashes::ripemd160;
                        let digest = ripemd160::Hash::hash(&v).to_byte_array();
                        push(stack, altstack.len(), digest.to_vec())?;
                    }
                    0xa7 => {
                        // OP_SHA1 is consensus-enabled (was stubbed → would fail post-milestone).
                        let v = pop(stack)?;
                        push(stack, altstack.len(), crypto::sha1(&v).to_vec())?;
                    }
                    0xa8 => {
                        let v = pop(stack)?;
                        push(stack, altstack.len(), crypto::sha256(&v).to_vec())?;
                    }
                    0xa9 => {
                        let v = pop(stack)?;
                        push(stack, altstack.len(), crypto::hash160(&v).to_vec())?;
                    }
                    0xaa => {
                        let v = pop(stack)?;
                        use bitcoin::hashes::sha256d;
                        let digest = sha256d::Hash::hash(&v).to_byte_array();
                        push(stack, altstack.len(), digest.to_vec())?;
                    }
                    0xab => {
                        // Tapscript: instruction index. Base/v0: scriptCode after this opcode.
                        // CONST_SCRIPTCODE already returned above, including unexecuted.
                        ctx.codeseparator_pos.set(this_pos);
                        ctx.codeseparator_script_off
                            .set(Some(byte_index.saturating_add(1)));
                    }
                    0xac => op_checksig(stack, altstack.len(), ctx, false)?,
                    0xad => op_checksig(stack, altstack.len(), ctx, true)?,
                    0xba => {
                        if ctx.sig_version != SigVersion::TapScript {
                            return Err(ConsensusError::Script("unknown opcode 0xba".into()));
                        }
                        op_checksigadd(stack, altstack.len(), ctx)?;
                    }
                    0xae => {
                        // BIP342: CHECKMULTISIG disabled in tapscript (hard fail).
                        let Some(pre) = PreTapscript::from_sig_version(ctx.sig_version) else {
                            return Err(ConsensusError::Script(
                                "CHECKMULTISIG disabled in tapscript".into(),
                            ));
                        };
                        op_checkmultisig(stack, altstack.len(), ctx, false, &mut op_count, pre)?;
                    }
                    0xaf => {
                        let Some(pre) = PreTapscript::from_sig_version(ctx.sig_version) else {
                            return Err(ConsensusError::Script(
                                "CHECKMULTISIGVERIFY disabled in tapscript".into(),
                            ));
                        };
                        op_checkmultisig(stack, altstack.len(), ctx, true, &mut op_count, pre)?;
                    }
                    0xb1 => {
                        // BIP65: pre-activation is NOP.
                        if !ctx.bip65_active {
                            continue;
                        }
                        require_n(stack, 1)?;
                        // BIP65 locktime: 5-byte script integer, minimal encoding when required.
                        let locktime = scriptnum_decode_width(stack.last().unwrap(), 5, rm)?;
                        if locktime < 0 {
                            return Err(ConsensusError::Script("CLTV negative".into()));
                        }
                        let tx_lock = ctx.tx.lock_time.to_consensus_u32() as i64;
                        let lock_is_time = locktime >= 500_000_000;
                        let tx_is_time = tx_lock >= 500_000_000;
                        if lock_is_time != tx_is_time {
                            return Err(ConsensusError::Script("CLTV type".into()));
                        }
                        if locktime > tx_lock {
                            return Err(ConsensusError::Script("CLTV".into()));
                        }
                        if ctx.tx.input[ctx.input_index.get()].sequence.is_final() {
                            return Err(ConsensusError::Script("CLTV final sequence".into()));
                        }
                    }
                    0xb2 => {
                        // BIP112: decode (5-byte) → disable-flag NOP → version < 2 fails
                        // (not NOP). docs/external_findings/004-csv-nop-and-scriptnum-width.md
                        if !ctx.bip112_active {
                            continue;
                        }
                        require_n(stack, 1)?;
                        let csv = scriptnum_decode_width(stack.last().unwrap(), 5, rm)?;
                        if csv < 0 {
                            return Err(ConsensusError::Script("CSV negative".into()));
                        }
                        if csv as u32 & (1 << 31) != 0 {
                            // disabled bit → NOP (before version gate)
                            continue;
                        }
                        // Core CheckSequence: tx.nVersion < 2 → fail (unsigned; RB-001).
                        if (ctx.tx.version.0 as u32) < 2 {
                            return Err(ConsensusError::Script("CSV version".into()));
                        }
                        let seq = ctx.tx.input[ctx.input_index.get()].sequence;
                        if !sequence_csv_ok(seq, csv as u32) {
                            return Err(ConsensusError::Script("CSV".into()));
                        }
                    }
                    0xb0 | 0xb3 | 0xb4 | 0xb5 | 0xb6 | 0xb7 | 0xb8 | 0xb9 => {}
                    _ => {
                        // OP_SUCCESS returned before this loop. Disabled opcodes
                        // already returned above.
                        return Err(ConsensusError::Script(format!(
                            "unknown opcode 0x{code:02x}"
                        )));
                    }
                }
            }
        }
    }

    if !cond_stack.is_empty() {
        return Err(ConsensusError::Script("unbalanced IF".into()));
    }
    Ok(true)
}

/// The type bit does not overlap the low 16, so `|` and `^` are the same mask.
#[cfg_attr(feature = "mutants", mutants::skip)]
#[doc(hidden)]
pub fn csv_locktime_mask(type_bit: u32) -> u32 {
    0x0000_ffff | type_bit
}

#[doc(hidden)]
pub fn sequence_csv_ok(seq: Sequence, csv: u32) -> bool {
    let seq_n = seq.to_consensus_u32();
    if seq_n & (1 << 31) != 0 {
        return false; // SEQUENCE_LOCKTIME_DISABLE_FLAG on input
    }
    let type_bit = 1 << 22;
    let mask = csv_locktime_mask(type_bit);
    let seq_masked = seq_n & mask;
    let csv_masked = csv & mask;
    let type_flag = type_bit;
    if (seq_masked ^ csv_masked) & type_flag != 0 {
        return false;
    }
    (csv_masked & 0xffff) <= (seq_masked & 0xffff)
}

#[doc(hidden)]
pub fn op_checksig(
    stack: &mut Vec<Vec<u8>>,
    alt_len: usize,
    ctx: &EvalContext<'_>,
    verify: bool,
) -> Result<(), ConsensusError> {
    let pubkey = pop(stack)?;
    let sig = pop(stack)?;
    let Some(pre) = PreTapscript::from_sig_version(ctx.sig_version) else {
        return op_checksig_tapscript(stack, alt_len, &sig, &pubkey, ctx, verify);
    };
    let ok = checksig_legacy(&sig, &pubkey, ctx, pre)?;
    if verify {
        if !ok {
            return Err(ConsensusError::Script("CHECKSIGVERIFY".into()));
        }
    } else {
        push(stack, alt_len, bool_encode(ok))?;
    }
    Ok(())
}

/// BIP342 OP_CHECKSIGADD: stack is `… sig n pubkey` → `… n` or `… n+1`.
#[doc(hidden)]
pub fn op_checksigadd(
    stack: &mut Vec<Vec<u8>>,
    alt_len: usize,
    ctx: &EvalContext<'_>,
) -> Result<(), ConsensusError> {
    require_n(stack, 3)?;
    let pubkey = pop(stack)?;
    let n_raw = pop(stack)?;
    let sig = pop(stack)?;
    let n = decode_i64(&n_raw, ctx.minimal_data)?;
    match tapscript_sig_result(&sig, &pubkey, ctx)? {
        TapSigResult::EmptySig => {
            push(stack, alt_len, scriptnum_encode(n))?;
        }
        TapSigResult::Valid => {
            push(stack, alt_len, scriptnum_encode(n.saturating_add(1)))?;
        }
    }
    Ok(())
}

/// BIP342 signature opcode outcomes for known/unknown keys.
#[doc(hidden)]
pub enum TapSigResult {
    /// Signature was the empty vector (soft fail: push 0 / n / fail VERIFY).
    EmptySig,
    /// Signature verified or unknown key type treated as success.
    Valid,
}

#[doc(hidden)]
pub fn op_checksig_tapscript(
    stack: &mut Vec<Vec<u8>>,
    alt_len: usize,
    sig: &[u8],
    pubkey: &[u8],
    ctx: &EvalContext<'_>,
    verify: bool,
) -> Result<(), ConsensusError> {
    match tapscript_sig_result(sig, pubkey, ctx)? {
        TapSigResult::EmptySig => {
            if verify {
                return Err(ConsensusError::Script("CHECKSIGVERIFY empty".into()));
            }
            // BIP342: push empty vector (not 0x00 byte).
            push(stack, alt_len, vec![])?;
        }
        TapSigResult::Valid => {
            if !verify {
                push(stack, alt_len, vec![0x01])?;
            }
        }
    }
    Ok(())
}

#[doc(hidden)]
pub fn tapscript_init_weight(tx: &Transaction, input_index: usize, sig_version: SigVersion) -> i64 {
    if sig_version != SigVersion::TapScript {
        return 0;
    }
    let size = tx
        .input
        .get(input_index)
        .map(|inp| bitcoin::consensus::encode::serialize(&inp.witness).len() as i64)
        .unwrap_or(0);
    TAPSCRIPT_VALIDATION_WEIGHT_OFFSET + size
}

/// Shared BIP342 CHECKSIG / CHECKSIGVERIFY / CHECKSIGADD validation core.
#[doc(hidden)]
pub fn tapscript_sig_result(
    sig: &[u8],
    pubkey: &[u8],
    ctx: &EvalContext<'_>,
) -> Result<TapSigResult, ConsensusError> {
    if !sig.is_empty() {
        let left = ctx.validation_weight_left.get() - TAPSCRIPT_VALIDATION_WEIGHT_PER_SIGOP;
        ctx.validation_weight_left.set(left);
        if left < 0 {
            return Err(ConsensusError::Script("tapscript validation weight".into()));
        }
    }
    if pubkey.is_empty() {
        return Err(ConsensusError::Script("tapscript empty pubkey".into()));
    }
    // Unknown public key type (not 32 bytes): treat signature as valid (soft-fork hook).
    if pubkey.len() != 32 {
        if sig.is_empty() {
            return Ok(TapSigResult::EmptySig);
        }
        return Ok(TapSigResult::Valid);
    }
    if sig.is_empty() {
        return Ok(TapSigResult::EmptySig);
    }
    if !checksig_schnorr(sig, pubkey, ctx)? {
        return Err(ConsensusError::Script("tapscript CHECKSIG failed".into()));
    }
    Ok(TapSigResult::Valid)
}

#[doc(hidden)]
pub fn op_checkmultisig(
    stack: &mut Vec<Vec<u8>>,
    alt_len: usize,
    ctx: &EvalContext<'_>,
    verify: bool,
    op_count: &mut usize,
    ver: PreTapscript,
) -> Result<(), ConsensusError> {
    // Pop order matches Core: n, n keys (top=last), m, m sigs (top=last), dummy.
    let n = decode_i64(&pop(stack)?, ctx.minimal_data)?;
    if !(0..=MAX_PUBKEYS_PER_MULTISIG).contains(&n) {
        return Err(ConsensusError::Script("multisig n".into()));
    }
    *op_count += n as usize;
    if *op_count > MAX_OPS_LEGACY {
        return Err(ConsensusError::Script("op count".into()));
    }
    // Pop n keys: first pop is stack top = last pushed. Core evaluates that
    // key first (encoding + match), so keep pop order (no reverse).
    let mut pubkeys = Vec::with_capacity(n as usize);
    for _ in 0..n {
        pubkeys.push(pop(stack)?);
    }
    let m = decode_i64(&pop(stack)?, ctx.minimal_data)?;
    if m < 0 || m > n {
        return Err(ConsensusError::Script("multisig m".into()));
    }
    let mut sigs = Vec::with_capacity(m as usize);
    for _ in 0..m {
        sigs.push(pop(stack)?);
    }
    let dummy = pop(stack)?;
    // BIP147 is SCRIPT_VERIFY_NULLDUMMY. Core does not add a witness-v0
    // special case. Confirm sets the flag for every segwit block.
    if !dummy.is_empty() && ctx.null_dummy {
        return Err(ConsensusError::Script("NULLDUMMY".into()));
    }

    // Core Base: FindAndDelete every sig, and drop bare OP_CODESEPARATOR,
    // before the key walk. One pass. A script with neither borrows.
    let original = script_code_bytes(ctx);
    let script_code: Cow<'_, [u8]> = if ver == PreTapscript::Base {
        let refs: Vec<&[u8]> = sigs.iter().map(|sig| sig.as_slice()).collect();
        let (code, deleted) = legacy_script_code(original, &refs)?;
        if ctx.const_scriptcode && deleted {
            return Err(ConsensusError::Script("SIG_FINDANDDELETE".into()));
        }
        code
    } else {
        Cow::Borrowed(original)
    };

    let f_success = checkmultisig_pairs(&sigs, &pubkeys, ctx, &script_code, ver)?;

    if !f_success && ctx.nullfail && sigs.iter().any(|s| !s.is_empty()) {
        return Err(ConsensusError::Script("NULLFAIL".into()));
    }

    if verify {
        if !f_success {
            return Err(ConsensusError::Script("CHECKMULTISIGVERIFY".into()));
        }
    } else {
        push(stack, alt_len, bool_encode(f_success))?;
    }
    Ok(())
}

#[doc(hidden)]
pub fn checkmultisig_pairs(
    sigs: &[Vec<u8>],
    pubkeys: &[Vec<u8>],
    ctx: &EvalContext<'_>,
    script_code: &[u8],
    ver: PreTapscript,
) -> Result<bool, ConsensusError> {
    // Core: start at last-pushed sig/key (index 0 after pop-order storage).
    // Advance key always; advance sig only on match. Encoding checks run only
    // for pairs actually tried (early exit skips unused invalid encodings).
    let mut f_success = true;
    let mut n_sigs = sigs.len();
    let mut n_keys = pubkeys.len();
    let mut isig = 0usize;
    let mut ikey = 0usize;
    while f_success && n_sigs > 0 {
        let f_ok = ecdsa_sig_matches(&sigs[isig], &pubkeys[ikey], ctx, script_code, ver)?;
        if f_ok {
            isig += 1;
            n_sigs -= 1;
        }
        ikey += 1;
        n_keys -= 1;
        if n_sigs > n_keys {
            f_success = false;
        }
    }
    Ok(f_success)
}

/// Direct push: length opcode, then PUSHDATA1/2/4. Empty data is the single byte `0x00`.
/// A one-byte payload is not rewritten as `OP_N`.
#[doc(hidden)]
pub fn encode_push(out: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n < usize::from(OP_PUSHDATA1) {
        out.push(n as u8);
    } else if n <= 0xff {
        out.push(OP_PUSHDATA1);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(OP_PUSHDATA2);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else {
        out.push(OP_PUSHDATA4);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
}

/// Remove every occurrence of a data-push of `data` from `script`.
///
/// Used for legacy (Base) CHECKSIG / CHECKMULTISIG so a signature cannot sign itself
/// when it appears inside scriptCode (mainnet block 290329: P2SH redeem embeds a sig).
///
/// Consensus: empty `data` is Core's `CScript() << vchSig` = the push `0x00`,
/// so an empty signature deletes every OP_0 opcode. The script is borrowed when
/// the push does not occur.
pub fn find_and_delete<'a>(script: &'a [u8], data: ScriptElem<'_>) -> Cow<'a, [u8]> {
    let raw = data.as_bytes();
    let mut needle = Vec::with_capacity(raw.len() + 5);
    encode_push(&mut needle, raw);
    legacy_script_code_needles(script, false, &[&needle]).0
}

/// Script bytes used as Base/WitnessV0 scriptCode (after OP_CODESEPARATOR).
#[doc(hidden)]
pub fn script_code_bytes<'a>(ctx: &'a EvalContext<'_>) -> &'a [u8] {
    let full = ctx.script_code.as_bytes();
    match ctx.codeseparator_script_off.get() {
        // The only writer is OP_CODESEPARATOR's byte index, which is in range.
        Some(off) => &full[off..],
        _ => full,
    }
}

/// When hashing a legacy (BASE) scriptCode, **skip every `OP_CODESEPARATOR`
/// opcode** (0xab).
///
/// This is distinct from codeseparator truncation (which only drops bytes
/// *before* the last executed CODESEPARATOR). Separators that remain *after*
/// that point are still omitted from the serialized scriptCode. Without this,
/// redeem scripts that embed CODESEPARATOR (e.g. mainnet block 443992 P2SH
/// multi-condition contracts) produce a wrong sighash and fail CHECKSIGVERIFY.
pub fn strip_op_codeseparator(script: &[u8]) -> Cow<'_, [u8]> {
    legacy_script_code_needles(script, true, &[]).0
}

/// One walk of a base scriptCode.
///
/// Drops a direct push of any signature when `drop_sig` is set by the needles,
/// and drops a bare `OP_CODESEPARATOR` when `drop_sep` is set. Push payloads
/// are not opcodes. The original bytes are returned when the walk drops nothing.
/// The bool is true when a signature push was dropped.
fn legacy_script_code<'a>(
    script: &'a [u8],
    sigs: &[&[u8]],
) -> Result<(Cow<'a, [u8]>, bool), ConsensusError> {
    let mut encoded = Vec::with_capacity(sigs.len());
    for sig in sigs {
        let raw = ScriptElem::new(sig)?.as_bytes();
        let mut needle = Vec::with_capacity(raw.len() + 5);
        encode_push(&mut needle, raw);
        encoded.push(needle);
    }
    let refs: Vec<&[u8]> = encoded.iter().map(|n| n.as_slice()).collect();
    Ok(legacy_script_code_needles(script, true, &refs))
}

fn legacy_script_code_needles<'a>(
    script: &'a [u8],
    drop_sep: bool,
    needles: &[&[u8]],
) -> (Cow<'a, [u8]>, bool) {
    let mut out: Option<Vec<u8>> = None;
    let mut deleted_sig = false;
    let mut i = 0usize;
    while i < script.len() {
        if let Some(needle) = needles
            .iter()
            .copied()
            .find(|needle| !needle.is_empty() && script[i..].starts_with(needle))
        {
            if out.is_none() {
                out = Some(script[..i].to_vec());
            }
            i += needle.len();
            deleted_sig = true;
            continue;
        }
        let op = script[i];
        match instruction_end(script, i) {
            None => {
                if let Some(buf) = out.as_mut() {
                    buf.push(op);
                } else if i + 1 < script.len() {
                    out = Some(script[..=i].to_vec());
                }
                break;
            }
            Some(end) => {
                if drop_sep && op == OP_CODESEPARATOR {
                    if out.is_none() {
                        out = Some(script[..i].to_vec());
                    }
                } else if let Some(buf) = out.as_mut() {
                    buf.extend_from_slice(&script[i..end]);
                }
                i = end;
            }
        }
    }
    (
        out.map(Cow::Owned).unwrap_or(Cow::Borrowed(script)),
        deleted_sig,
    )
}

/// End of the instruction at `i`, or `None` when a push length is truncated.
/// A short payload still ends at the last available byte.
fn instruction_end(script: &[u8], i: usize) -> Option<usize> {
    let op = script[i];
    let mut j = i + 1;
    let n = if (1..=OP_PUSHBYTES_75).contains(&op) {
        op as usize
    } else if op == OP_PUSHDATA1 {
        if j >= script.len() {
            return None;
        }
        let n = script[j] as usize;
        j += 1;
        n
    } else if op == OP_PUSHDATA2 {
        if j + 1 >= script.len() {
            return None;
        }
        let n = u16::from_le_bytes([script[j], script[j + 1]]) as usize;
        j += 2;
        n
    } else if op == OP_PUSHDATA4 {
        if j + 3 >= script.len() {
            return None;
        }
        let n =
            u32::from_le_bytes([script[j], script[j + 1], script[j + 2], script[j + 3]]) as usize;
        j += 4;
        n
    } else {
        0
    };
    if n > 0 {
        j = (j + n).min(script.len());
    }
    Some(j)
}

/// Legacy / witness-v0 OP_CHECKSIG (Core `EvalChecksigPreTapscript`).
///
/// Base FindAndDeletes this signature from scriptCode. NULLFAIL hard-fails a
/// non-empty signature that does not verify.
#[doc(hidden)]
pub fn checksig_legacy(
    sig: &[u8],
    pubkey: &[u8],
    ctx: &EvalContext<'_>,
    ver: PreTapscript,
) -> Result<bool, ConsensusError> {
    let base = script_code_bytes(ctx);
    let prepared = if ver == PreTapscript::Base {
        let (code, deleted) = legacy_script_code(base, &[sig])?;
        if ctx.const_scriptcode && deleted {
            return Err(ConsensusError::Script("SIG_FINDANDDELETE".into()));
        }
        code
    } else {
        Cow::Borrowed(base)
    };
    let script_code = prepared.as_ref();
    let ok = ecdsa_sig_matches(sig, pubkey, ctx, script_code, ver)?;
    if !ok && ctx.nullfail && !sig.is_empty() {
        return Err(ConsensusError::Script("NULLFAIL".into()));
    }
    Ok(ok)
}

/// One ECDSA signature / pubkey comparison against `script_code`.
///
/// Encoding failures under DERSIG / LOW_S / STRICTENC / WITNESS_PUBKEYTYPE
/// hard-fail, then an empty signature is false. A signature that does not verify
/// is false; NULLFAIL belongs to the calling opcode (CHECKMULTISIG applies it
/// only after the whole key walk fails).
#[doc(hidden)]
pub fn ecdsa_sig_matches(
    sig: &[u8],
    pubkey: &[u8],
    ctx: &EvalContext<'_>,
    script_code: &[u8],
    ver: PreTapscript,
) -> Result<bool, ConsensusError> {
    checksig_legacy_encodings(sig, pubkey, ctx, ver)?;
    if sig.is_empty() {
        return Ok(false);
    }

    // Pre-DERSIG: malformed DER that slipped encoding → false.
    let Ok((ecdsa_sig, sighash_ty)) = crypto::parse_der_sig(sig, false) else {
        return Ok(false);
    };
    let Ok(pk) = crypto::parse_pubkey(pubkey) else {
        return Ok(false);
    };
    let Ok(sighash) = sighash_for_script(ctx, sighash_ty, script_code, ver) else {
        return Ok(false);
    };
    Ok(crypto::verify_ecdsa(sighash, &ecdsa_sig, &pk))
}

/// Core `CheckSignatureEncoding` then `CheckPubKeyEncoding`. An empty
/// signature skips only the signature checks.
#[doc(hidden)]
pub fn checksig_legacy_encodings(
    sig: &[u8],
    pubkey: &[u8],
    ctx: &EvalContext<'_>,
    ver: PreTapscript,
) -> Result<(), ConsensusError> {
    if !sig.is_empty() {
        check_signature_encoding(sig, ctx)?;
    }
    if ctx.strictenc && !crypto::is_compressed_or_uncompressed_pubkey(pubkey) {
        return Err(ConsensusError::Script("PUBKEYTYPE".into()));
    }
    if ctx.witness_pubkeytype
        && ver == PreTapscript::WitnessV0
        && !crypto::is_compressed_pubkey(pubkey)
    {
        return Err(ConsensusError::Script("WITNESS_PUBKEYTYPE".into()));
    }
    Ok(())
}

#[doc(hidden)]
pub fn check_signature_encoding(sig: &[u8], ctx: &EvalContext<'_>) -> Result<(), ConsensusError> {
    let need_der = ctx.bip66_active || ctx.low_s || ctx.strictenc;
    if need_der && !crypto::is_valid_signature_encoding(sig) {
        return Err(ConsensusError::Script("SIG_DER".into()));
    }
    if ctx.low_s {
        // LOW_S already required BIP66 encoding above, so the lax parse hits.
        let (ecdsa, _) = crypto::parse_der_sig(sig, false).expect("BIP66 signature parses");
        if !crypto::is_low_der_s(&ecdsa) {
            return Err(ConsensusError::Script("SIG_HIGH_S".into()));
        }
    }
    if ctx.strictenc && !crypto::is_defined_hashtype(sig) {
        return Err(ConsensusError::Script("SIG_HASHTYPE".into()));
    }
    Ok(())
}

/// BIP340 Schnorr verify for a 32-byte x-only pubkey in tapscript (leaf sighash).
#[doc(hidden)]
pub fn checksig_schnorr(
    sig: &[u8],
    pubkey: &[u8],
    ctx: &EvalContext<'_>,
) -> Result<bool, ConsensusError> {
    debug_assert_eq!(pubkey.len(), 32);
    let (sig_bytes, sighash_ty) = if sig.len() == 64 {
        (sig, bitcoin::sighash::TapSighashType::Default)
    } else if sig.len() == 65 {
        // BIP342: sighash byte must not be 0x00.
        if sig[64] == 0x00 {
            return Ok(false);
        }
        let ty = bitcoin::sighash::TapSighashType::from_consensus_u8(sig[64])
            .map_err(|_| ConsensusError::Script("tapscript sighash".into()))?;
        (&sig[..64], ty)
    } else {
        return Ok(false);
    };
    let xonly = bitcoin::key::XOnlyPublicKey::from_slice(pubkey)
        .map_err(|_| ConsensusError::Script("tapscript xonly".into()))?;
    // `from_slice` rejects only a length other than 64. `sig_bytes` is that long.
    let schnorr = bitcoin::secp256k1::schnorr::Signature::from_slice(sig_bytes)
        .expect("64-byte schnorr slice");
    let exec = ctx.tapscript.as_ref().ok_or_else(|| {
        ConsensusError::Script("invariant: tapscript spend without tapleaf hash".into())
    })?;
    let sighash = exec.signature_hash(sighash_ty, ctx.codeseparator_pos.get())?;
    let msg = bitcoin::secp256k1::Message::from_digest(sighash);
    Ok(crypto::SECP.with(|secp| secp.verify_schnorr(&schnorr, &msg, &xonly).is_ok()))
}

#[doc(hidden)]
pub fn sighash_for_script(
    ctx: &EvalContext<'_>,
    ty_raw: u32,
    script_bytes: &[u8],
    ver: PreTapscript,
) -> Result<[u8; 32], ConsensusError> {
    let script_code = Script::from_bytes(script_bytes);
    match ver {
        PreTapscript::Base => {
            // Raw hashtype 0 is not SIGHASH_ALL=1. The caller already dropped
            // a bare OP_CODESEPARATOR.
            let mut slot = ctx.cache.borrow_mut();
            let cache = slot.get_or_insert_with(|| SighashCache::new(ctx.tx));
            let h = cache
                .legacy_signature_hash(ctx.input_index.get(), script_code, ty_raw)
                .map_err(|_| ConsensusError::Script("legacy sighash".into()))?;
            Ok(h.to_byte_array())
        }
        PreTapscript::WitnessV0 => crypto::bip143_p2wsh_signature_hash(
            ctx.tx,
            ctx.input_index,
            script_code,
            ctx.amount,
            ty_raw,
            ctx.pre.as_ref(),
        ),
    }
}

#[doc(hidden)]
pub fn push(stack: &mut Vec<Vec<u8>>, alt_len: usize, v: Vec<u8>) -> Result<(), ConsensusError> {
    if stack.len().saturating_add(alt_len).saturating_add(1) > MAX_STACK_SIZE {
        return Err(ConsensusError::Script("stack size".into()));
    }
    stack.push(v);
    Ok(())
}

#[doc(hidden)]
pub fn pop(stack: &mut Vec<Vec<u8>>) -> Result<Vec<u8>, ConsensusError> {
    stack
        .pop()
        .ok_or_else(|| ConsensusError::Script("stack empty".into()))
}

#[doc(hidden)]
pub fn require_n(stack: &[Vec<u8>], n: usize) -> Result<(), ConsensusError> {
    if stack.len() < n {
        return Err(ConsensusError::Script("stack empty".into()));
    }
    Ok(())
}

#[doc(hidden)]
pub fn decode_i64(
    v: &[u8],
    require_minimal: bool,
) -> Result<i64, rbitcoin_primitives::ScriptNumError> {
    rbitcoin_primitives::scriptnum_decode(v, require_minimal)
}

/// BIP342 MINIMALIF: IF/NOTIF argument is empty vector or single-byte 0x01 only.
#[doc(hidden)]
pub fn is_minimal_if_arg(v: &[u8]) -> bool {
    v.is_empty() || v == [0x01]
}

#[doc(hidden)]
pub fn bool_encode(b: bool) -> Vec<u8> {
    if b {
        vec![1]
    } else {
        vec![]
    }
}

/// Data must use the shortest opcode form.
#[doc(hidden)]
pub fn check_minimal_push(data: ScriptElem<'_>, opcode: u8) -> bool {
    let data = data.as_bytes();
    if data.is_empty() {
        return opcode == rbitcoin_primitives::OP_0;
    }
    if data.len() == 1 && data[0] >= 1 && data[0] <= 16 {
        return opcode == OP_RESERVED + data[0];
    }
    if data.len() == 1 && data[0] == 0x81 {
        return opcode == OP_1NEGATE;
    }
    if data.len() <= usize::from(OP_PUSHBYTES_75) {
        return opcode as usize == data.len();
    }
    if data.len() <= 255 {
        return opcode == OP_PUSHDATA1;
    }
    // 256..=520. PUSHDATA4 cannot be minimal: the element type stops at 520.
    opcode == OP_PUSHDATA2
}

#[doc(hidden)]
pub fn bin_arith(
    stack: &mut Vec<Vec<u8>>,
    alt_len: usize,
    require_minimal: bool,
    f: impl Fn(i64, i64) -> i64,
) -> Result<(), ConsensusError> {
    let b = decode_i64(&pop(stack)?, require_minimal)?;
    let a = decode_i64(&pop(stack)?, require_minimal)?;
    push(stack, alt_len, scriptnum_encode(f(a, b)))
}

#[doc(hidden)]
pub fn bin_cmp(
    stack: &mut Vec<Vec<u8>>,
    alt_len: usize,
    require_minimal: bool,
    f: impl Fn(i64, i64) -> bool,
) -> Result<(), ConsensusError> {
    let b = decode_i64(&pop(stack)?, require_minimal)?;
    let a = decode_i64(&pop(stack)?, require_minimal)?;
    push(stack, alt_len, bool_encode(f(a, b)))
}
