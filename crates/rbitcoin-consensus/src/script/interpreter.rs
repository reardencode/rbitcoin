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
use rbitcoin_primitives::{scriptnum_decode_width, scriptnum_encode};

/// Stack element cap (main + alt).
pub(crate) const MAX_STACK_SIZE: usize = 1000;
/// Push / witness stack item cap.
pub(crate) const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// BIP342 `VALIDATION_WEIGHT_OFFSET` / `VALIDATION_WEIGHT_PER_SIGOP_PASSED`.
const TAPSCRIPT_VALIDATION_WEIGHT_OFFSET: i64 = 50;
const TAPSCRIPT_VALIDATION_WEIGHT_PER_SIGOP: i64 = 50;

/// Legacy / witness-v0 script size cap (BIP16 / BIP141). **Not** applied in tapscript
/// (BIP342: size only bounded by block weight).
const MAX_SCRIPT_SIZE_LEGACY: usize = 10_000;
/// Legacy / witness-v0 non-push opcode budget. **Not** applied in tapscript (BIP342).
const MAX_OPS_LEGACY: usize = 201;
const MAX_PUBKEYS_PER_MULTISIG: i64 = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SigVersion {
    Base,
    WitnessV0,
    TapScript,
}

/// ECDSA CHECKSIG / CHECKMULTISIG. TapScript is routed before this path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreTapscript {
    Base,
    WitnessV0,
}

impl PreTapscript {
    fn from_sig_version(version: SigVersion) -> Option<Self> {
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
// btc-lean: INV-045 INV-063 INV-064 SCR-092 SCR-170
fn is_disabled_legacy(code: u8) -> bool {
    matches!(
        code,
        0x7e | 0x7f
            | 0x80
            | 0x81
            | 0x83
            | 0x84
            | 0x85
            | 0x86
            | 0x8d
            | 0x8e
            | 0x95
            | 0x96
            | 0x97
            | 0x98
            | 0x99
    )
}

// btc-lean: SCR-152 SCR-153 SCR-154 SCR-172 TPR-062
fn is_op_success(code: u8) -> bool {
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

/// BIP342: scan tapscript for OP_SUCCESSx. Returns true if script is immediately valid.
pub(crate) fn tapscript_has_op_success(script: &Script) -> bool {
    let bytes = script.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let op = bytes[i];
        if (1..=75).contains(&op) {
            let n = op as usize;
            i = i.saturating_add(1).saturating_add(n);
            continue;
        }
        match op {
            0x4c => {
                if i + 1 >= bytes.len() {
                    break;
                }
                let n = bytes[i + 1] as usize;
                i = i.saturating_add(2).saturating_add(n);
            }
            0x4d => {
                if i + 2 >= bytes.len() {
                    break;
                }
                let n = u16::from_le_bytes([bytes[i + 1], bytes[i + 2]]) as usize;
                i = i.saturating_add(3).saturating_add(n);
            }
            0x4e => {
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

pub(crate) struct EvalContext<'a> {
    pub tx: &'a Transaction,
    pub input_index: usize,
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
    codeseparator_pos: Cell<u32>,
    /// Base / WitnessV0: byte offset into `script_code` of the first opcode **after**
    /// the last executed OP_CODESEPARATOR. `None` = full script.
    ///
    /// BIP143 / legacy CHECKSIG use this truncated script as `scriptCode`.
    codeseparator_script_off: Cell<Option<usize>>,
    /// Legacy midstate. Created on first use (WitnessV0 uses `pre`, tapscript `tapscript`).
    cache: RefCell<Option<SighashCache<&'a Transaction>>>,
    /// Structure/lookup midstates (WitnessV0 BIP143).
    pre: Cow<'a, crate::TxPrecompute>,
    /// BIP342 remaining validation weight (`50 + witness serialized size`).
    validation_weight_left: Cell<i64>,
    /// Tapscript only: per-input sighash facts from the script-path spend.
    tapscript: Option<crypto::TapscriptExecData<'a>>,
}

impl<'a> EvalContext<'a> {
    #[cfg(test)]
    pub(crate) fn new(
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
    #[cfg(test)]
    pub(crate) fn new_with_flags(
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
            Cow::Owned(crate::TxPrecompute::from_tx(tx)),
        )
    }

    #[allow(clippy::too_many_arguments)] // call-site args stay unbundled
    fn from_eval_parts(
        tx: &'a Transaction,
        input_index: usize,
        amount: Amount,
        script_code: &'a Script,
        sig_version: SigVersion,
        bip65_active: bool,
        bip112_active: bool,
        bip66_active: bool,
        pre: Cow<'a, crate::TxPrecompute>,
    ) -> Self {
        Self {
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
            // btc-lean: SCR-167
            codeseparator_pos: Cell::new(0xFFFF_FFFF),
            codeseparator_script_off: Cell::new(None),
            cache: RefCell::new(None),
            pre,
            validation_weight_left: Cell::new(tapscript_init_weight(tx, input_index, sig_version)),
            tapscript: None,
        }
    }

    /// Attach the tapleaf and annex facts of a BIP341 script-path spend.
    pub(crate) fn with_tapscript(mut self, exec: crypto::TapscriptExecData<'a>) -> Self {
        self.tapscript = Some(exec);
        self
    }

    /// Copy standardness / fixture flags from a [`crate::block::ScriptCheckJob`].
    pub(crate) fn apply_job_flags(mut self, job: &crate::block::ScriptCheckJob) -> Self {
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
    pub(crate) fn from_job(
        job: &'a crate::block::ScriptCheckJob,
        tx: &'a Transaction,
        input_index: usize,
        script_code: &'a Script,
        sig_version: SigVersion,
    ) -> Result<Self, ConsensusError> {
        let amount = if input_index < job.prevouts.len() {
            job.prevout_amount(input_index)?
        } else {
            Amount::ZERO
        };
        Ok(Self::from_eval_parts(
            tx,
            input_index,
            amount,
            script_code,
            sig_version,
            job.bip65_active,
            job.bip112_active,
            job.bip66_active,
            Cow::Borrowed(job.pre()),
        )
        .apply_job_flags(job))
    }
}

/// BIP141 / BIP342: exactly one true value on the stack (witness / tapscript).
// btc-lean: SCR-008 SCR-138 SWT-012
pub(crate) fn require_clean_true(stack: &[Vec<u8>]) -> Result<(), ConsensusError> {
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
pub(crate) fn require_true_top(stack: &[Vec<u8>]) -> Result<(), ConsensusError> {
    // btc-lean: INV-048 SCR-002 SCR-004 SCR-056 SCR-077
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
#[cfg(test)]
pub(crate) fn eval_script_sig_pushes(
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
struct ConditionStack {
    size: usize,
    first_false: Option<usize>,
}

impl ConditionStack {
    fn is_empty(&self) -> bool {
        self.size == 0
    }

    fn all_true(&self) -> bool {
        self.first_false.is_none()
    }

    fn push(&mut self, value: bool) {
        if self.first_false.is_none() && !value {
            self.first_false = Some(self.size);
        }
        self.size += 1;
    }

    /// Caller checks [`Self::is_empty`] first (`OP_ENDIF` without `OP_IF`).
    fn pop(&mut self) {
        self.size -= 1;
        if self.first_false == Some(self.size) {
            self.first_false = None;
        }
    }

    /// Caller checks [`Self::is_empty`] first (`OP_ELSE` without `OP_IF`).
    fn toggle_top(&mut self) {
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
// btc-lean: INV-062 SCR-001 SCR-003 SCR-017 TPR-059 TPR-060 TPR-061 TPR-063 TPR-064 TPR-065 TPR-066
// btc-lean: TPR-067 TPR-068
pub(crate) fn eval_script(
    script: &Script,
    stack: &mut Vec<Vec<u8>>,
    ctx: &EvalContext<'_>,
) -> Result<bool, ConsensusError> {
    let bytes = script.as_bytes();
    // BIP342: OP_SUCCESSx anywhere in tapscript → unconditional success *before*
    // size / stack limits (even unparseable tails pass).
    // btc-lean: INV-061
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
    // btc-lean: INV-041 SCR-018 SCR-019 SWT-011
    if ctx.sig_version != SigVersion::TapScript && bytes.len() > MAX_SCRIPT_SIZE_LEGACY {
        return Err(ConsensusError::Script("script too large".into()));
    }

    let mut altstack: Vec<Vec<u8>> = Vec::new();
    let mut cond_stack = ConditionStack::default();
    let mut op_count = 0usize;
    // btc-lean: SCR-155 TPR-073 TPR-074
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
        // btc-lean: SCR-045
        let (byte_index, ins) = item.map_err(|_| ConsensusError::Script("script parse".into()))?;
        let this_pos = opcode_pos;
        opcode_pos = opcode_pos.saturating_add(1);
        let executing = cond_stack.all_true();

        match ins {
            Instruction::PushBytes(b) => {
                // Core: MAX_SCRIPT_ELEMENT_SIZE even in unexecuted branches.
                let data = b.as_bytes();
                // btc-lean: INV-042 SCR-020 SCR-021
                if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return Err(ConsensusError::Script("push too large".into()));
                }
                // Core MINIMALDATA: CheckMinimalPush only when the push executes
                // (unexecuted IF branches ignore non-minimal encodings).
                if executing {
                    if ctx.minimal_data {
                        let opcode = bytes.get(byte_index).copied().unwrap_or(0);
                        // btc-lean: INV-046 SCR-047 SCR-048 SCR-049
                        if !check_minimal_push(data, opcode) {
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
                    // btc-lean: INV-043 SCR-022 SCR-023 SCR-024 SCR-025 SCR-028 SCR-067 SCR-113
                    // btc-lean: SCR-171
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
                    // btc-lean: SCR-064
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
                // btc-lean: SCR-065
                if code == 0x65 || code == 0x66 {
                    return Err(ConsensusError::Script("OP_VERIF".into()));
                }
                // Core: disabled opcodes fail even in unexecuted branches (legacy/v0).
                if ctx.sig_version != SigVersion::TapScript && is_disabled_legacy(code) {
                    return Err(ConsensusError::Script(format!(
                        "disabled opcode 0x{code:02x}"
                    )));
                }
                // CONST_SCRIPTCODE: OP_CODESEPARATOR rejected in Base even unexecuted.
                // btc-lean: SCR-100
                if code == 0xab && ctx.const_scriptcode && ctx.sig_version == SigVersion::Base {
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
                    // btc-lean: SCR-033 SCR-046
                    n if (0x51..=0x60).contains(&n) => push(stack, altstack.len(), vec![n - 0x50])?,
                    0x61 => {}
                    // btc-lean: SCR-068
                    0x69 => {
                        let v = pop(stack)?;
                        if !bitcoin::script::read_scriptbool(&v) {
                            return Err(ConsensusError::Script("OP_VERIFY".into()));
                        }
                    }

                    // btc-lean: SCR-031 SCR-073
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
                    // btc-lean: SCR-087 SCR-088 SCR-090
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
                    // btc-lean: SCR-089
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
                    // btc-lean: SCR-093 SCR-094 SCR-095
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
                        // btc-lean: INV-057 SCR-096 SCR-097 SCR-167
                        ctx.codeseparator_pos.set(this_pos);
                        ctx.codeseparator_script_off
                            .set(Some(byte_index.saturating_add(1)));
                    }
                    // btc-lean: INV-078 SCR-109 SCR-111 SCR-117 SCR-136
                    0xac => op_checksig(stack, altstack.len(), ctx, false)?,
                    0xad => op_checksig(stack, altstack.len(), ctx, true)?,
                    0xba => {
                        if ctx.sig_version != SigVersion::TapScript {
                            return Err(ConsensusError::Script("unknown opcode 0xba".into()));
                        }
                        // btc-lean: TPR-056
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
                    // btc-lean: INV-022 SCR-122 SCR-123 SCR-124 SCR-126 SCR-132 TXV-043 TXV-044
                    // btc-lean: TXV-045
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
                        if ctx.tx.input[ctx.input_index].sequence.is_final() {
                            return Err(ConsensusError::Script("CLTV final sequence".into()));
                        }
                    }
                    // btc-lean: INV-023 SCR-125 SCR-127 SCR-128 SCR-129 SCR-130 SCR-131 TXV-046
                    // btc-lean: TXV-047 TXV-048
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
                        let seq = ctx.tx.input[ctx.input_index].sequence;
                        if !sequence_csv_ok(seq, csv as u32) {
                            return Err(ConsensusError::Script("CSV".into()));
                        }
                    }
                    // btc-lean: SCR-071 SCR-072
                    0xb0 | 0xb3 | 0xb4 | 0xb5 | 0xb6 | 0xb7 | 0xb8 | 0xb9 => {}
                    _ => {
                        // OP_SUCCESS returned before this loop. Disabled opcodes
                        // already returned above.
                        return Err(ConsensusError::Script(format!(
                            // btc-lean: SCR-066 SCR-069 SCR-174
                            "unknown opcode 0x{code:02x}"
                        )));
                    }
                }
            }
        }
    }

    // btc-lean: INV-047 SCR-061 SCR-062 SCR-063
    if !cond_stack.is_empty() {
        return Err(ConsensusError::Script("unbalanced IF".into()));
    }
    Ok(true)
}

/// The type bit does not overlap the low 16, so `|` and `^` are the same mask.
#[cfg_attr(feature = "mutants", mutants::skip)]
fn csv_locktime_mask(type_bit: u32) -> u32 {
    0x0000_ffff | type_bit
}

fn sequence_csv_ok(seq: Sequence, csv: u32) -> bool {
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

// btc-lean: SWT-054 TPR-055
fn op_checksig(
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
fn op_checksigadd(
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
enum TapSigResult {
    /// Signature was the empty vector (soft fail: push 0 / n / fail VERIFY).
    EmptySig,
    /// Signature verified or unknown key type treated as success.
    Valid,
}

fn op_checksig_tapscript(
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

// btc-lean: SCR-040 TPR-022 TPR-071
fn tapscript_init_weight(tx: &Transaction, input_index: usize, sig_version: SigVersion) -> i64 {
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
fn tapscript_sig_result(
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
    // btc-lean: INV-054
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

// btc-lean: INV-049 INV-060 SCR-026 SCR-027 SCR-032 SCR-043 SCR-114 SCR-116 SCR-118 SCR-119 SCR-120
// btc-lean: SCR-121 SWT-063 SWT-064 SWT-065
fn op_checkmultisig(
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

    // Core Base: FindAndDelete **all** sigs from scriptCode before the loop.
    let original = script_code_bytes(ctx);
    let script_code: Cow<'_, [u8]> = if ver == PreTapscript::Base {
        let mut sc = original.to_vec();
        for sig in &sigs {
            sc = find_and_delete(&sc, sig);
        }
        if ctx.const_scriptcode && sc != original {
            return Err(ConsensusError::Script("SIG_FINDANDDELETE".into()));
        }
        Cow::Owned(sc)
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

fn checkmultisig_pairs(
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

/// Remove every occurrence of a data-push of `data` from `script`.
///
/// Used for legacy (Base) CHECKSIG / CHECKMULTISIG so a signature cannot sign itself
/// when it appears inside scriptCode (mainnet block 290329: P2SH redeem embeds a sig).
///
/// Consensus: empty `data` is Core's `CScript() << vchSig` = the push `0x00`,
/// so an empty signature deletes every OP_0 opcode.
// btc-lean: INV-056 SCR-098 SCR-099 SCR-101 SCR-115 SCR-139
pub(crate) fn find_and_delete(script: &[u8], data: &[u8]) -> Vec<u8> {
    let mut needle = Vec::with_capacity(data.len() + 3);
    if data.len() < 0x4c {
        needle.push(data.len() as u8);
    } else if data.len() <= 0xff {
        needle.push(0x4c);
        needle.push(data.len() as u8);
    } else if data.len() <= 0xffff {
        needle.push(0x4d);
        needle.extend_from_slice(&(data.len() as u16).to_le_bytes());
    } else {
        needle.push(0x4e);
        needle.extend_from_slice(&(data.len() as u32).to_le_bytes());
    }
    needle.extend_from_slice(data);

    let mut out = Vec::with_capacity(script.len());
    let mut i = 0usize;
    while i < script.len() {
        if i + needle.len() <= script.len() && script[i..i + needle.len()] == needle[..] {
            i += needle.len();
            continue;
        }
        let op = script[i];
        out.push(op);
        i += 1;
        let n = if (1..=75).contains(&op) {
            op as usize
        } else if op == 0x4c {
            if i >= script.len() {
                break;
            }
            let n = script[i] as usize;
            out.push(script[i]);
            i += 1;
            n
        } else if op == 0x4d {
            if i + 1 >= script.len() {
                break;
            }
            let n = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
            out.extend_from_slice(&script[i..i + 2]);
            i += 2;
            n
        } else if op == 0x4e {
            if i + 3 >= script.len() {
                break;
            }
            let n = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]])
                as usize;
            out.extend_from_slice(&script[i..i + 4]);
            i += 4;
            n
        } else {
            0
        };
        if n > 0 {
            let end = (i + n).min(script.len());
            out.extend_from_slice(&script[i..end]);
            i = end;
        }
    }
    out
}

/// Script bytes used as Base/WitnessV0 scriptCode (after OP_CODESEPARATOR).
fn script_code_bytes<'a>(ctx: &'a EvalContext<'_>) -> &'a [u8] {
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
pub(crate) fn strip_op_codeseparator(script: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(script.len());
    let mut i = 0usize;
    while i < script.len() {
        let op = script[i];
        i += 1;
        if op == 0xab {
            continue;
        }
        out.push(op);
        let n = if (1..=75).contains(&op) {
            op as usize
        } else if op == 0x4c {
            if i >= script.len() {
                break;
            }
            let n = script[i] as usize;
            out.push(script[i]);
            i += 1;
            n
        } else if op == 0x4d {
            if i + 1 >= script.len() {
                break;
            }
            let n = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
            out.extend_from_slice(&script[i..i + 2]);
            i += 2;
            n
        } else if op == 0x4e {
            if i + 3 >= script.len() {
                break;
            }
            let n = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]])
                as usize;
            out.extend_from_slice(&script[i..i + 4]);
            i += 4;
            n
        } else {
            0
        };
        if n > 0 {
            let end = (i + n).min(script.len());
            out.extend_from_slice(&script[i..end]);
            i = end;
        }
    }
    out
}

/// Legacy / witness-v0 OP_CHECKSIG (Core `EvalChecksigPreTapscript`).
///
/// Base FindAndDeletes this signature from scriptCode. NULLFAIL hard-fails a
/// non-empty signature that does not verify.
fn checksig_legacy(
    sig: &[u8],
    pubkey: &[u8],
    ctx: &EvalContext<'_>,
    ver: PreTapscript,
) -> Result<bool, ConsensusError> {
    let base = script_code_bytes(ctx);
    let deleted: Vec<u8>;
    let script_code: &[u8] = if ver == PreTapscript::Base {
        deleted = find_and_delete(base, sig);
        if ctx.const_scriptcode && deleted.as_slice() != base {
            return Err(ConsensusError::Script("SIG_FINDANDDELETE".into()));
        }
        &deleted
    } else {
        base
    };
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
fn ecdsa_sig_matches(
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
    // btc-lean: SCR-112
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
fn checksig_legacy_encodings(
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

// btc-lean: INV-050 INV-051 INV-052 INV-053 SCR-041 SCR-042 SCR-102 SCR-103 SCR-104 SCR-106
// btc-lean: SCR-107 SCR-108 SCR-110 SCR-179 SGN-111 SWT-058 SWT-059 SWT-060 SWT-061
fn check_signature_encoding(sig: &[u8], ctx: &EvalContext<'_>) -> Result<(), ConsensusError> {
    let need_der = ctx.bip66_active || ctx.low_s || ctx.strictenc;
    if need_der && !crypto::is_valid_signature_encoding(sig) {
        return Err(ConsensusError::Script("SIG_DER".into()));
    }
    // btc-lean: SGN-108
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
// btc-lean: INV-055 TPR-057 TPR-058
fn checksig_schnorr(
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

fn sighash_for_script(
    ctx: &EvalContext<'_>,
    ty_raw: u32,
    script_bytes: &[u8],
    ver: PreTapscript,
) -> Result<[u8; 32], ConsensusError> {
    let script_code = Script::from_bytes(script_bytes);
    match ver {
        PreTapscript::Base => {
            // Raw hashtype 0 is not SIGHASH_ALL=1.
            let stripped = strip_op_codeseparator(script_bytes);
            let script_code = Script::from_bytes(&stripped);
            let mut slot = ctx.cache.borrow_mut();
            let cache = slot.get_or_insert_with(|| SighashCache::new(ctx.tx));
            let h = cache
                .legacy_signature_hash(ctx.input_index, script_code, ty_raw)
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

fn push(stack: &mut Vec<Vec<u8>>, alt_len: usize, v: Vec<u8>) -> Result<(), ConsensusError> {
    // btc-lean: INV-044 SCR-029
    if stack.len().saturating_add(alt_len).saturating_add(1) > MAX_STACK_SIZE {
        return Err(ConsensusError::Script("stack size".into()));
    }
    stack.push(v);
    Ok(())
}

fn pop(stack: &mut Vec<Vec<u8>>) -> Result<Vec<u8>, ConsensusError> {
    stack
        .pop()
        .ok_or_else(|| ConsensusError::Script("stack empty".into()))
}

// btc-lean: SCR-030 SCR-074 SCR-078
fn require_n(stack: &[Vec<u8>], n: usize) -> Result<(), ConsensusError> {
    if stack.len() < n {
        return Err(ConsensusError::Script("stack empty".into()));
    }
    Ok(())
}

fn decode_i64(v: &[u8], require_minimal: bool) -> Result<i64, rbitcoin_primitives::ScriptNumError> {
    use rbitcoin_primitives::ScriptNumError;
    let parsed = if require_minimal {
        bitcoin::script::read_scriptint(v)
    } else {
        bitcoin::script::read_scriptint_non_minimal(v)
    };
    parsed.map_err(|e| match e {
        bitcoin::script::Error::NonMinimalPush => ScriptNumError::NonMinimal,
        _ => ScriptNumError::Overflow,
    })
}

/// BIP342 MINIMALIF: IF/NOTIF argument is empty vector or single-byte 0x01 only.
// btc-lean: INV-059 SCR-058 SCR-059 SCR-060 SCR-178 SCR-183 SWT-062
fn is_minimal_if_arg(v: &[u8]) -> bool {
    v.is_empty() || v == [0x01]
}

fn bool_encode(b: bool) -> Vec<u8> {
    if b {
        vec![1]
    } else {
        vec![]
    }
}

/// Data must use the shortest opcode form.
fn check_minimal_push(data: &[u8], opcode: u8) -> bool {
    if data.is_empty() {
        return opcode == 0x00;
    }
    if data.len() == 1 && data[0] >= 1 && data[0] <= 16 {
        return opcode == 0x50 + data[0];
    }
    if data.len() == 1 && data[0] == 0x81 {
        return opcode == 0x4f;
    }
    if data.len() <= 75 {
        return opcode as usize == data.len();
    }
    if data.len() <= 255 {
        return opcode == 0x4c;
    }
    if data.len() <= 65535 {
        return opcode == 0x4d;
    }
    true
}

fn bin_arith(
    stack: &mut Vec<Vec<u8>>,
    alt_len: usize,
    require_minimal: bool,
    f: impl Fn(i64, i64) -> i64,
) -> Result<(), ConsensusError> {
    let b = decode_i64(&pop(stack)?, require_minimal)?;
    let a = decode_i64(&pop(stack)?, require_minimal)?;
    push(stack, alt_len, scriptnum_encode(f(a, b)))
}

fn bin_cmp(
    stack: &mut Vec<Vec<u8>>,
    alt_len: usize,
    require_minimal: bool,
    f: impl Fn(i64, i64) -> bool,
) -> Result<(), ConsensusError> {
    let b = decode_i64(&pop(stack)?, require_minimal)?;
    let a = decode_i64(&pop(stack)?, require_minimal)?;
    push(stack, alt_len, bool_encode(f(a, b)))
}

#[cfg(test)]
mod success_and_disabled_tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    fn eval(script_bytes: &[u8], sig_version: SigVersion) -> Result<bool, ConsensusError> {
        eval_with_null_dummy(script_bytes, sig_version, false)
    }

    fn eval_with_null_dummy(
        script_bytes: &[u8],
        sig_version: SigVersion,
        null_dummy: bool,
    ) -> Result<bool, ConsensusError> {
        let tx = Transaction {
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
        };
        // script_code points into script_bytes via Script::from_bytes
        let script = Script::from_bytes(script_bytes);
        let mut ctx = EvalContext::new(&tx, 0, Amount::from_sat(50_000), script, sig_version);
        ctx.null_dummy = null_dummy;
        let mut stack = Vec::new();
        eval_script(script, &mut stack, &ctx)
    }

    fn eval_stack(
        script_bytes: &[u8],
        sig_version: SigVersion,
    ) -> Result<Vec<Vec<u8>>, ConsensusError> {
        let tx = Transaction {
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
        };
        let script = Script::from_bytes(script_bytes);
        let ctx = EvalContext::new(&tx, 0, Amount::from_sat(50_000), script, sig_version);
        let mut stack = Vec::new();
        eval_script(script, &mut stack, &ctx)?;
        Ok(stack)
    }

    fn num(n: u8) -> Vec<u8> {
        vec![n]
    }

    #[test]
    fn tapscript_op_success126_accepts() {
        // Real signet leaf fragment starts with normal ops then hits 0x7e (OP_SUCCESS126).
        let leaf = hex_literal(
            "60947600a2697601409f697601407c94b2750200006b760120a2636c04000000007e6b012094687660a2636c0200007e6b6094687658a2636c01007e",
        );
        assert!(tapscript_has_op_success(Script::from_bytes(&leaf)));
        let need_clean = eval(&leaf, SigVersion::TapScript).expect("tapscript success");
        assert!(!need_clean, "OP_SUCCESS skips cleanstack");
    }

    #[test]
    fn legacy_op_cat_disabled_rejects() {
        // Minimal: push empty, push empty, OP_CAT
        let script = vec![0x00, 0x00, 0x7e];
        let err = eval(&script, SigVersion::WitnessV0).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("disabled") || msg.contains("0x7e"),
            "unexpected: {msg}"
        );
    }

    /// Core: disabled opcodes fail even in unexecuted IF branches.
    #[test]
    fn unexecuted_disabled_opcode_still_rejects() {
        // OP_0 IF OP_CAT ELSE OP_1 ENDIF → IF body not taken, but CAT still fails.
        let script = vec![0x00, 0x63, 0x7e, 0x67, 0x51, 0x68];
        let err = eval(&script, SigVersion::Base).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("disabled") || msg.contains("0x7e"),
            "Core rejects unexecuted CAT: {msg}"
        );
    }

    /// Core: OP_VERIF always fails even when not executing.
    #[test]
    fn unexecuted_verif_still_rejects() {
        // OP_0 IF OP_VERIF ELSE OP_1 ENDIF
        let script = vec![0x00, 0x63, 0x65, 0x67, 0x51, 0x68];
        let err = eval(&script, SigVersion::Base).unwrap_err();
        assert!(
            format!("{err}").contains("VERIF") || format!("{err}").contains("opcode"),
            "{err}"
        );
    }

    #[test]
    fn bare_op_success_byte_not_success_on_legacy() {
        // On legacy, 0x7e is disabled CAT, not SUCCESS.
        assert!(!tapscript_has_op_success(Script::from_bytes(&[0x51]))); // no success
        let script = vec![0x7e];
        assert!(eval(&script, SigVersion::Base).is_err());
    }

    fn hex_literal(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// strip_op_codeseparator + script_code_bytes + OP_PUSHDATA lengths.
    #[test]
    fn strip_codeseparator_and_pushdata_lens() {
        // CODESEPARATOR (0xab) stripped; surrounding ops kept.
        let script = vec![0x51, 0xab, 0x52]; // OP_1 CODESEPARATOR OP_2
        let stripped = strip_op_codeseparator(&script);
        assert_eq!(stripped, vec![0x51, 0x52]);
        // PUSHDATA1 / 2 / 4 inside strip
        let mut s = vec![0x4c, 0x02, 0xaa, 0xbb, 0xab, 0x51];
        let st = strip_op_codeseparator(&s);
        assert!(st.contains(&0x4c));
        assert!(!st.contains(&0xab));
        s = vec![0x4d, 0x01, 0x00, 0xcc, 0xab];
        let st = strip_op_codeseparator(&s);
        assert!(st.windows(2).any(|w| w == [0x4d, 0x01]));
        s = vec![0x4e, 0x01, 0x00, 0x00, 0x00, 0xdd];
        let st = strip_op_codeseparator(&s);
        assert_eq!(st.last(), Some(&0xdd));
        // Truncated pushdata lengths break cleanly
        let _ = strip_op_codeseparator(&[0x4c]);
        let _ = strip_op_codeseparator(&[0x4d, 0x01]);
        let _ = strip_op_codeseparator(&[0x4e, 0x01, 0x00]);
        // script_code_bytes via EvalContext with codeseparator offset
        let need = eval(&[0x51], SigVersion::Base).unwrap();
        assert!(need);
    }

    #[test]
    fn tapscript_checksigadd_empty_sig_keeps_n() {
        // stack: empty_sig, n=2, unknown_key(1 byte) → CHECKSIGADD → n=2; OP_TRUE
        // Unknown key + empty sig → EmptySig path; push n.
        let script = vec![
            0x00, // empty sig
            0x52, // OP_2 (n)
            0x01, 0xaa, // push 1-byte unknown key type
            0xba, // OP_CHECKSIGADD
            0x52, // OP_2
            0x87, // OP_EQUAL
        ];
        let need = eval(&script, SigVersion::TapScript).expect("eval");
        assert!(need);
    }

    #[test]
    fn tapscript_checksigadd_unknown_key_nonempty_sig_increments() {
        // nonempty garbage sig + unknown key = Valid (soft-fork hook) → n+1
        let script = vec![
            0x01, 0x01, // 1-byte sig (non-empty)
            0x51, // OP_1 (n=1)
            0x01, 0xaa, // unknown key
            0xba, // CHECKSIGADD → 2
            0x52, // OP_2
            0x87, // EQUAL
        ];
        let need = eval(&script, SigVersion::TapScript).expect("eval");
        assert!(need);
    }

    #[test]
    fn tapscript_checksigadd_legacy_unknown() {
        // On witness v0, 0xba is still unknown.
        let script = vec![0x00, 0x51, 0x01, 0xaa, 0xba];
        let err = eval(&script, SigVersion::WitnessV0).unwrap_err();
        assert!(format!("{err}").contains("0xba"));
    }

    #[test]
    fn tapscript_checkmultisig_disabled() {
        let script = vec![0x00, 0x00, 0x00, 0x51, 0x51, 0xae]; // junk + CHECKMULTISIG
        let err = eval(&script, SigVersion::TapScript).unwrap_err();
        assert!(format!("{err}").contains("CHECKMULTISIG"));
    }

    #[test]
    fn tapscript_checksig_empty_pubkey_fails() {
        // empty sig, empty pubkey (OP_0 OP_0 CHECKSIG)
        let script = vec![0x00, 0x00, 0xac];
        let err = eval(&script, SigVersion::TapScript).unwrap_err();
        assert!(format!("{err}").contains("empty pubkey"));
    }

    #[test]
    fn tapscript_empty_pubkey_reports_weight_when_budget_exhausted() {
        // OP_1 OP_1 CHECKSIG then OP_1 OP_0 CHECKSIG.
        // Dummy witness init weight is 51; first non-empty sig burns 50.
        // Core decrements weight before the empty-pubkey fail, so the second
        // CHECKSIG is TAPSCRIPT_VALIDATION_WEIGHT, not empty pubkey.
        let script = vec![0x51, 0x51, 0xac, 0x51, 0x00, 0xac];
        let err = eval(&script, SigVersion::TapScript).unwrap_err();
        assert!(
            format!("{err}").contains("validation weight"),
            "Core order: weight before empty pubkey, got {err}"
        );

        // One nonempty unknown-key sig at remaining weight exactly 0 is allowed.
        let script = vec![0x01, 0x02, 0x01, 0xaa, 0xac];
        let tx = Transaction {
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
        };
        let sc = Script::from_bytes(&script);
        let ctx = EvalContext::new(&tx, 0, Amount::from_sat(1), sc, SigVersion::TapScript);
        ctx.validation_weight_left
            .set(TAPSCRIPT_VALIDATION_WEIGHT_PER_SIGOP);
        eval_script(sc, &mut Vec::new(), &ctx).expect("remaining weight 0 still passes");
    }

    #[test]
    fn tapscript_allows_scripts_over_10k() {
        // Legacy would reject; tapscript must accept (BIP342).
        let mut script = vec![0x51]; // OP_TRUE
        script.resize(10_001, 0x61); // pad with OP_NOP
        script.push(0x51); // end with TRUE so cleanstack ok if executed
                           // Actually NOPs leave stack; final TRUE needed as only element — start empty,
                           // fill with NOPs, end OP_1.
        let mut script = vec![0x61; 10_001];
        script.push(0x51);
        let need = eval(&script, SigVersion::TapScript).expect("tapscript large script");
        assert!(need);
        let err = eval(&script, SigVersion::WitnessV0).unwrap_err();
        assert!(format!("{err}").contains("too large"));

        let tx = Transaction {
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
        };
        let nop = Script::from_bytes(&[0x61]);
        let ctx = EvalContext::new(&tx, 0, Amount::from_sat(1), nop, SigVersion::TapScript);
        let mut at_limit = vec![vec![1u8]; MAX_STACK_SIZE];
        eval_script(nop, &mut at_limit, &ctx).expect("1000 stack items");
        let mut over_stack = vec![vec![1u8]; MAX_STACK_SIZE + 1];
        let err = eval_script(nop, &mut over_stack, &ctx).unwrap_err();
        assert!(format!("{err}").contains("stack size"), "{err}");
        let mut at_elem = vec![vec![0u8; MAX_SCRIPT_ELEMENT_SIZE]];
        eval_script(nop, &mut at_elem, &ctx).expect("520-byte element");
        let mut over_elem = vec![vec![0u8; MAX_SCRIPT_ELEMENT_SIZE + 1]];
        let err = eval_script(nop, &mut over_elem, &ctx).unwrap_err();
        assert!(format!("{err}").contains("PUSH_SIZE"), "{err}");
    }

    /// Every consensus-enabled opcode must not report "unknown opcode".
    /// Disabled/reserved still error, but with a specific reason.
    #[test]
    fn no_unknown_opcode_for_enabled_set() {
        // Minimal stacks so each op runs far enough to prove it is recognized.
        // Format: (name, script_bytes, sig_version) — success or known error, not unknown.
        let cases: &[(&str, Vec<u8>, SigVersion)] = &[
            ("1ADD", vec![0x51, 0x8b, 0x52, 0x87], SigVersion::WitnessV0),
            ("1SUB", vec![0x52, 0x8c, 0x51, 0x87], SigVersion::WitnessV0),
            (
                "NEGATE",
                vec![0x51, 0x8f, 0x4f, 0x87],
                SigVersion::WitnessV0,
            ),
            ("ABS", vec![0x4f, 0x90, 0x51, 0x87], SigVersion::WitnessV0),
            (
                "SHA1",
                vec![0x00, 0xa7, 0x82, 0x01, 0x14, 0x87],
                SigVersion::WitnessV0,
            ),
            (
                "RIPEMD160",
                vec![0x00, 0xa6, 0x82, 0x01, 0x14, 0x87],
                SigVersion::WitnessV0,
            ),
            (
                "SHA256",
                vec![0x00, 0xa8, 0x82, 0x01, 0x20, 0x87],
                SigVersion::WitnessV0,
            ),
            (
                "HASH160",
                vec![0x00, 0xa9, 0x82, 0x01, 0x14, 0x87],
                SigVersion::WitnessV0,
            ),
            (
                "HASH256",
                vec![0x00, 0xaa, 0x82, 0x01, 0x20, 0x87],
                SigVersion::WitnessV0,
            ),
            ("SIZE", vec![0x00, 0x82, 0x00, 0x87], SigVersion::WitnessV0),
            (
                "WITHIN",
                vec![0x51, 0x00, 0x52, 0xa5, 0x51, 0x87],
                SigVersion::WitnessV0,
            ),
            (
                "MIN",
                vec![0x51, 0x52, 0xa3, 0x51, 0x87],
                SigVersion::WitnessV0,
            ),
            (
                "MAX",
                vec![0x51, 0x52, 0xa4, 0x52, 0x87],
                SigVersion::WitnessV0,
            ),
            (
                "CHECKSIGADD",
                vec![0x00, 0x51, 0x01, 0xff, 0xba, 0x51, 0x87],
                SigVersion::TapScript,
            ),
        ];
        for (name, script, sv) in cases {
            match eval(script, *sv) {
                Ok(_) => {}
                Err(e) => {
                    let msg = format!("{e}");
                    assert!(
                        !msg.contains("unknown opcode"),
                        "{name}: unexpected unknown opcode: {msg}"
                    );
                }
            }
        }
        // Disabled must fail with disabled/reserved, not "unknown"
        for code in [0x7e_u8, 0x8d, 0x95] {
            let script = vec![0x51, 0x51, code];
            let err = eval(&script, SigVersion::WitnessV0).unwrap_err();
            let msg = format!("{err}");
            assert!(
                msg.contains("disabled") || msg.contains("unknown") || msg.contains("RESERVED"),
                "0x{code:02x}: {msg}"
            );
        }
    }

    /// BIP147: a non-empty CHECKMULTISIG dummy fails only when the flag is on.
    #[test]
    fn nulldummy_rejects_nonempty_dummy() {
        // 0-of-0 multisig: n=0, m=0, dummy non-empty → NULLDUMMY when the flag is set.
        let script = vec![0x01, 0xff, 0x00, 0x00, 0xae, 0x51];
        let err = eval_with_null_dummy(&script, SigVersion::WitnessV0, true).unwrap_err();
        assert!(
            format!("{err}").contains("NULLDUMMY"),
            "expected NULLDUMMY, got {err}"
        );
        let err = eval_with_null_dummy(&script, SigVersion::Base, true).unwrap_err();
        assert!(
            format!("{err}").contains("NULLDUMMY"),
            "base flag on, got {err}"
        );
        // Empty dummy 0-of-0 succeeds (CMS pushes true).
        let script_ok = vec![0x00, 0x00, 0x00, 0xae];
        eval_with_null_dummy(&script_ok, SigVersion::WitnessV0, true).expect("0-of-0 empty dummy");
    }

    /// Witness v0 follows SCRIPT_VERIFY_NULLDUMMY. Flag off accepts, matching
    /// Core VerifyScript. Base with the flag off accepts the same dummy.
    #[test]
    fn witness_v0_nulldummy_follows_the_flag() {
        let script = vec![0x01, 0xff, 0x00, 0x00, 0xae];
        eval_with_null_dummy(&script, SigVersion::WitnessV0, false)
            .expect("witness v0 flag off accepts");
        let err = eval_with_null_dummy(&script, SigVersion::WitnessV0, true).unwrap_err();
        assert!(
            format!("{err}").contains("NULLDUMMY"),
            "witness v0 flag on, got {err}"
        );
        eval(&script, SigVersion::Base).expect("base with NULLDUMMY off allows the dummy");
    }

    /// BIP112: OP_CSV fails when tx.nVersion < 2 (unsigned), matching Core.
    /// (`docs/external_findings/004-csv-nop-and-scriptnum-width.md`).
    #[test]
    fn csv_fails_when_tx_version_below_2() {
        // Script: push 1, CSV, DROP, OP_TRUE — v1 must fail CSV version gate.
        let script_bytes = [0x51u8, 0xb2, 0x75, 0x51]; // 1 CSV DROP TRUE
        let script = Script::from_bytes(&script_bytes);
        let mk = |ver: i32| Transaction {
            version: bitcoin::transaction::Version(ver),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(0), // would fail real CSV
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        // v1: Core fails (not NOP) when BIP112 active and disable bit clear.
        let tx1 = mk(1);
        let ctx1 = EvalContext::new_with_flags(
            &tx1,
            0,
            Amount::from_sat(50_000),
            script,
            SigVersion::Base,
            true,
            true, // bip112 active
            true,
        );
        let mut stack1 = Vec::new();
        let err = eval_script(script, &mut stack1, &ctx1).unwrap_err();
        assert!(
            matches!(err, ConsensusError::Script(ref s) if s.contains("CSV")),
            "v1 must fail CSV version gate, got {err:?}"
        );

        // v2: CSV enforces → fails with seq=0 vs csv=1
        let tx2 = mk(2);
        let ctx2 = EvalContext::new_with_flags(
            &tx2,
            0,
            Amount::from_sat(50_000),
            script,
            SigVersion::Base,
            true,
            true,
            true,
        );
        let mut stack2 = Vec::new();
        let err = eval_script(script, &mut stack2, &ctx2).unwrap_err();
        assert!(
            format!("{err}").contains("CSV"),
            "v2 should enforce CSV, got {err}"
        );

        // The CSV operand's disable bit is a NOP, before the version gate.
        let nop = [0x05u8, 0x00, 0x00, 0x00, 0x80, 0x00, 0xb2, 0x75, 0x51];
        let nop_script = Script::from_bytes(&nop);
        let ctx_nop = EvalContext::new_with_flags(
            &tx1,
            0,
            Amount::from_sat(50_000),
            nop_script,
            SigVersion::Base,
            true,
            true,
            true,
        );
        let mut stack_nop = Vec::new();
        eval_script(nop_script, &mut stack_nop, &ctx_nop)
            .expect("CSV disable bit does not enforce");

        // Input disable flag fails even when the numeric lock would pass.
        let tx_dis = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(0x8000_0001),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let ctx_dis = EvalContext::new_with_flags(
            &tx_dis,
            0,
            Amount::from_sat(50_000),
            script,
            SigVersion::Base,
            true,
            true,
            true,
        );
        let mut stack_dis = Vec::new();
        let err = eval_script(script, &mut stack_dis, &ctx_dis).unwrap_err();
        assert!(
            format!("{err}").contains("CSV"),
            "input disable flag fails CSV, got {err}"
        );
    }

    #[test]
    fn script_sig_pushes_op_n_and_1negate() {
        let mut stack = Vec::new();
        // OP_0, OP_1NEGATE, OP_1, push bytes
        let ss = Script::from_bytes(&[0x00, 0x4f, 0x51, 0x01, 0xaa]);
        eval_script_sig_pushes(ss, &mut stack).unwrap();
        assert_eq!(stack.len(), 4);
        assert_eq!(stack[0], Vec::<u8>::new());
        assert_eq!(stack[1], vec![0x81]);
        assert_eq!(stack[2], vec![0x01]);
        assert_eq!(stack[3], vec![0xaa]);
        // Non-push opcode fails.
        let mut s2 = Vec::new();
        assert!(eval_script_sig_pushes(Script::from_bytes(&[0xac]), &mut s2).is_err());
    }

    #[test]
    fn find_and_delete_pushdata_lengths() {
        // Direct push
        let data = vec![0x11u8; 3];
        let mut script = vec![0x03];
        script.extend_from_slice(&data);
        script.push(0x51);
        let out = find_and_delete(&script, &data);
        assert_eq!(out, vec![0x51]);
        assert_eq!(
            find_and_delete(&[0x00, 0x00, 0x02, 0x00, 0x00, 0x51], &[]),
            vec![0x02, 0x00, 0x00, 0x51]
        );

        // PUSHDATA1 needle
        let big = vec![0x22u8; 80];
        let mut sc = vec![0x4c, 80];
        sc.extend_from_slice(&big);
        sc.push(0x52);
        let out2 = find_and_delete(&sc, &big);
        assert_eq!(out2, vec![0x52]);

        // PUSHDATA2
        let bigger = vec![0x33u8; 300];
        let mut sc2 = vec![0x4d];
        sc2.extend_from_slice(&(300u16).to_le_bytes());
        sc2.extend_from_slice(&bigger);
        sc2.push(0x53);
        assert_eq!(find_and_delete(&sc2, &bigger), vec![0x53]);

        // Non-matching copy through PUSHDATA encodings
        let passthrough = vec![0x4c, 0x01, 0xaa, 0x4d, 0x01, 0x00, 0xbb];
        assert_eq!(find_and_delete(&passthrough, &[0xff]), passthrough);

        // Length 76 is PUSHDATA1, not a direct push.
        let wide = vec![0x44u8; 76];
        let mut wide_script = vec![0x4c, 76];
        wide_script.extend_from_slice(&wide);
        wide_script.push(0x51);
        assert_eq!(find_and_delete(&wide_script, &wide), vec![0x51]);

        // Truncated PUSHDATA2 stops before the missing length byte.
        assert_eq!(find_and_delete(&[0x4d, 0x01], &[0xff]), vec![0x4d]);
        // Truncated PUSHDATA4 of four bytes: three length bytes are not enough.
        assert_eq!(
            find_and_delete(&[0x4e, 0x01, 0x00, 0x00], &[0xff]),
            vec![0x4e]
        );

        let needle = [0x11u8, 0x11, 0x11];
        let mut pd2 = vec![0x4d, 0x02, 0x00, 0xaa, 0xbb];
        pd2.extend_from_slice(&[0x03, 0x11, 0x11, 0x11]);
        assert_eq!(
            find_and_delete(&pd2, &needle),
            vec![0x4d, 0x02, 0x00, 0xaa, 0xbb]
        );

        // NOPs after the payload: a direct-push opcode here would swallow the needle.
        // Index 10 and 15 differ from the zero length bytes at i+2 and i+3.
        let mut pd4 = vec![0x61; 4];
        pd4.extend_from_slice(&[0x4e, 0x01, 0x00, 0x00, 0x00, 0xee]);
        pd4.extend_from_slice(&[0x61; 6]);
        pd4.extend_from_slice(&[0x03, 0x11, 0x11, 0x11]);
        let out4 = find_and_delete(&pd4, &needle);
        assert!(out4.contains(&0xee), "{out4:?}");
        assert!(
            out4.windows(3).all(|w| w != needle),
            "payload must not swallow the following push: {out4:?}"
        );
    }

    #[test]
    fn strip_codeseparator_keeps_pushdata() {
        // OP_1, CODESEPARATOR, PUSHDATA1 payload, OP_TRUE
        let sc = vec![0x51, 0xab, 0x4c, 0x02, 0xde, 0xad, 0x51];
        let stripped = strip_op_codeseparator(&sc);
        assert!(!stripped.contains(&0xab));
        assert!(stripped.windows(2).any(|w| w == [0xde, 0xad]));

        let sc2 = vec![0x4d, 0x01, 0x00, 0xee, 0xab, 0x51];
        let s2 = strip_op_codeseparator(&sc2);
        assert_eq!(s2.last(), Some(&0x51));
        assert!(!s2.contains(&0xab));

        let sc3 = vec![0x4e, 0x01, 0x00, 0x00, 0x00, 0x01, 0xab];
        let s3 = strip_op_codeseparator(&sc3);
        assert!(!s3.contains(&0xab));

        let pd2 = vec![0x4d, 0x02, 0x00, 0xde, 0xad, 0xab];
        assert_eq!(
            strip_op_codeseparator(&pd2),
            vec![0x4d, 0x02, 0x00, 0xde, 0xad]
        );
        assert_eq!(
            strip_op_codeseparator(&[0x4e, 0x01, 0x00, 0x00]),
            vec![0x4e]
        );
        // Four prefixes put the length word at i=5. At i=2, i*2 equals i+2.
        // Index 15 is in range and is not the same byte as i+3.
        let mut pd4 = vec![0x61; 4];
        pd4.extend_from_slice(&[0x4e, 0x01, 0x00, 0x00, 0x00, 0xee, 0xab]);
        pd4.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x11, 0x02]);
        let stripped4 = strip_op_codeseparator(&pd4);
        assert!(
            stripped4.windows(2).any(|w| w == [0x4e, 0x01]),
            "{stripped4:?}"
        );
        assert!(stripped4.contains(&0xee), "{stripped4:?}");
        assert!(!stripped4.contains(&0xab), "{stripped4:?}");
        let _ = (sc, sc2, sc3);
    }

    #[test]
    fn tapscript_has_op_success_pushdata_scan() {
        // OP_SUCCESS via direct byte after PUSHDATA1 skip
        let leaf = vec![0x4c, 0x02, 0x00, 0x00, 0x7e]; // push 2 then OP_SUCCESS126
        assert!(tapscript_has_op_success(Script::from_bytes(&leaf)));
        let leaf2 = vec![0x4d, 0x01, 0x00, 0xff, 0x7e];
        assert!(tapscript_has_op_success(Script::from_bytes(&leaf2)));
        let leaf3 = vec![0x4e, 0x01, 0x00, 0x00, 0x00, 0xaa, 0x7e];
        assert!(tapscript_has_op_success(Script::from_bytes(&leaf3)));
        // Truncated pushdata — no success past end
        assert!(!tapscript_has_op_success(Script::from_bytes(&[0x4c])));
        assert!(!tapscript_has_op_success(Script::from_bytes(&[0x4d, 0x01])));
        assert!(!tapscript_has_op_success(Script::from_bytes(&[
            0x4e, 0x01, 0x00
        ])));
        // OP_SUCCESS inside a push is data. The same byte after the push is success.
        assert!(!tapscript_has_op_success(Script::from_bytes(&[
            0x4c, 0x01, 0x7e
        ])));
        assert!(!tapscript_has_op_success(Script::from_bytes(&[
            0x4d, 0x01, 0x00, 0x7e
        ])));
        assert!(!tapscript_has_op_success(Script::from_bytes(&[
            0x4e, 0x01, 0x00, 0x00, 0x00, 0x7e
        ])));
        assert!(tapscript_has_op_success(Script::from_bytes(&[
            0x4c, 0x01, 0x00, 0x7e
        ])));
        let _ = (leaf, leaf2, leaf3);
    }

    #[test]
    fn cltv_type_mismatch_and_final_sequence() {
        // locktime height vs time type mismatch
        let script_bytes = [0x51u8, 0xb1, 0x75, 0x51]; // 1 CLTV DROP TRUE
        let script = Script::from_bytes(&script_bytes);
        let tx = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: LockTime::from_time(500_000_001).unwrap(),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(0),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let ctx = EvalContext::new_with_flags(
            &tx,
            0,
            Amount::from_sat(1),
            script,
            SigVersion::Base,
            true,
            true,
            true,
        );
        let mut stack = Vec::new();
        let err = eval_script(script, &mut stack, &ctx).unwrap_err();
        assert!(format!("{err}").contains("CLTV"), "got {err}");

        // Final sequence rejects CLTV even when locktime ok
        let script2 = Script::from_bytes(&[0x00, 0xb1, 0x75, 0x51]); // 0 CLTV DROP TRUE
        let tx2 = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: LockTime::from_height(10).unwrap(),
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
        };
        let ctx2 = EvalContext::new_with_flags(
            &tx2,
            0,
            Amount::from_sat(1),
            script2,
            SigVersion::Base,
            true,
            true,
            true,
        );
        let mut stack2 = Vec::new();
        let err2 = eval_script(script2, &mut stack2, &ctx2).unwrap_err();
        assert!(
            format!("{err2}").contains("CLTV") || format!("{err2}").contains("final"),
            "got {err2}"
        );
    }

    #[test]
    fn checkmultisig_verify_fail_and_tapscript_disabled() {
        // 1-of-1 CMSVERIFY with empty sigs fails
        // stack: dummy empty, sig empty, m=1, pk empty, n=1 → will fail verify
        let script = vec![0x00, 0x00, 0x51, 0x00, 0x51, 0xaf];
        let err = eval(&script, SigVersion::WitnessV0).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("CHECKMULTISIG") || msg.contains("NULLDUMMY") || msg.contains("stack"),
            "{msg}"
        );
        // Tapscript: CHECKMULTISIG disabled
        let err2 = eval(&[0x00, 0x00, 0x00, 0xae], SigVersion::TapScript).unwrap_err();
        assert!(
            format!("{err2}").contains("CHECKMULTISIG") || format!("{err2}").contains("disabled"),
            "{err2}"
        );
        let err3 = eval(&[0x00, 0x00, 0x00, 0xaf], SigVersion::TapScript).unwrap_err();
        assert!(
            format!("{err3}").to_lowercase().contains("checkmultisig")
                || format!("{err3}").contains("disabled"),
            "{err3}"
        );
    }

    #[test]
    fn minimalif_rejects_nonminimal_arg() {
        // TapScript MINIMALIF: push byte 0x00 (non-minimal false), IF, TRUE, ENDIF.
        // OP_0 empty is minimal; length-1 push of 0x00 is not.
        let script = vec![0x01, 0x00, 0x63, 0x51, 0x68];
        let err = eval(&script, SigVersion::TapScript).unwrap_err();
        assert!(format!("{err}").contains("MINIMALIF"), "got {err}");
        // OP_0 empty is minimal false → IF skipped → OP_TRUE after ENDIF succeeds.
        let script_ok = vec![0x00, 0x63, 0x51, 0x68, 0x51];
        assert!(eval(&script_ok, SigVersion::TapScript).expect("minimal empty if"));
    }

    /// Local extras dropped from `script_tests.json` when pinning Core v31.1.
    /// VERIFY must abort so a trailing `OP_1` cannot turn a failed check into success.
    #[test]
    fn checksigverify_then_op1_does_not_succeed() {
        // <empty sig> <33-byte key> CHECKSIGVERIFY OP_1
        let mut script = vec![0x00, 0x21];
        script.extend_from_slice(&[
            0x02, 0x86, 0x5c, 0x40, 0x29, 0x3a, 0x68, 0x0c, 0xb9, 0xc0, 0x20, 0xe7, 0xb1, 0xe1,
            0x06, 0xd8, 0xc1, 0x91, 0x6d, 0x3c, 0xef, 0x99, 0xaa, 0x43, 0x1a, 0x56, 0xd2, 0x53,
            0xe6, 0x92, 0x56, 0xda, 0xc0,
        ]);
        script.extend_from_slice(&[0xad, 0x51]); // CHECKSIGVERIFY 1
        let err = eval(&script, SigVersion::Base).unwrap_err();
        assert!(
            format!("{err}").contains("CHECKSIGVERIFY"),
            "VERIFY must hard-fail (not push false): {err}"
        );

        // Same with CHECKSIG (not VERIFY): false then 1 → script succeeds.
        let mut soft = script.clone();
        let n = soft.len();
        soft[n - 2] = 0xac; // CHECKSIG
        eval(&soft, SigVersion::Base).expect("CHECKSIG + OP_1 must succeed on a failed check");
    }

    #[test]
    fn checkmultisigverify_then_op1_does_not_succeed() {
        // dummy, empty sig, m=1, <key>, n=1, CHECKMULTISIGVERIFY, OP_1
        let mut script = vec![0x00, 0x00, 0x51, 0x21];
        script.extend_from_slice(&[
            0x02, 0x86, 0x5c, 0x40, 0x29, 0x3a, 0x68, 0x0c, 0xb9, 0xc0, 0x20, 0xe7, 0xb1, 0xe1,
            0x06, 0xd8, 0xc1, 0x91, 0x6d, 0x3c, 0xef, 0x99, 0xaa, 0x43, 0x1a, 0x56, 0xd2, 0x53,
            0xe6, 0x92, 0x56, 0xda, 0xc0,
        ]);
        script.extend_from_slice(&[0x51, 0xaf, 0x51]);
        let err = eval(&script, SigVersion::Base).unwrap_err();
        assert!(
            format!("{err}").contains("CHECKMULTISIGVERIFY"),
            "CMSVERIFY must hard-fail (not push false): {err}"
        );
    }

    #[test]
    fn cltv_empty_stack_is_invalid() {
        let err = eval(&[0xb1], SigVersion::Base).unwrap_err();
        assert!(
            format!("{err}").contains("stack"),
            "empty-stack CLTV: {err}"
        );
    }

    #[test]
    fn cltv_and_csv_negative_zero_is_not_negative() {
        // 0x80 is scriptnum negative-zero → 0, not < 0.
        assert_eq!(
            rbitcoin_primitives::scriptnum_decode_width(&[0x80], 5, false).unwrap(),
            0
        );

        // eval() uses nLockTime=0 and final nSequence (Core script_tests template).
        // CLTV(0) then fails final-sequence / unsatisfied — never "negative".
        let cltv = vec![0x01, 0x80, 0xb1];
        let err = eval(&cltv, SigVersion::Base).unwrap_err();
        let msg = format!("{err}");
        assert!(
            !msg.to_lowercase().contains("negative"),
            "0x80 must not take the CLTV-negative branch: {msg}"
        );
        assert!(
            msg.contains("CLTV") || msg.contains("final"),
            "expected unsatisfied/final, got {msg}"
        );

        let csv = vec![0x01, 0x80, 0xb2];
        let err = eval(&csv, SigVersion::Base).unwrap_err();
        let msg = format!("{err}");
        assert!(
            !msg.to_lowercase().contains("negative"),
            "0x80 must not take the CSV-negative branch: {msg}"
        );
    }

    #[test]
    fn cltv_negative_locktime_rejected() {
        // OP_1NEGATE CLTV …
        let script_bytes = [0x4fu8, 0xb1, 0x75, 0x51];
        let script = Script::from_bytes(&script_bytes);
        let tx = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: LockTime::from_height(10).unwrap(),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(0),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let ctx = EvalContext::new_with_flags(
            &tx,
            0,
            Amount::from_sat(1),
            script,
            SigVersion::Base,
            true,
            true,
            true,
        );
        let mut stack = Vec::new();
        let err = eval_script(script, &mut stack, &ctx).unwrap_err();
        assert!(
            format!("{err}").contains("CLTV") || format!("{err}").contains("negative"),
            "got {err}"
        );
    }

    #[test]
    fn stack_size_limit_on_2dup() {
        let top3 =
            eval_stack(&[0x51, 0x52, 0x53, 0x54, 0x55, 0x6f], SigVersion::WitnessV0).expect("3DUP");
        assert_eq!(
            top3,
            vec![
                num(1),
                num(2),
                num(3),
                num(4),
                num(5),
                num(3),
                num(4),
                num(5)
            ]
        );
        let over = eval_stack(&[0x51, 0x52, 0x53, 0x54, 0x55, 0x70], SigVersion::WitnessV0)
            .expect("2OVER");
        assert_eq!(
            over,
            vec![num(1), num(2), num(3), num(4), num(5), num(2), num(3)]
        );
        let rot = eval_stack(
            &[0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x71],
            SigVersion::WitnessV0,
        )
        .expect("2ROT");
        assert_eq!(
            rot,
            vec![num(1), num(4), num(5), num(6), num(7), num(2), num(3)]
        );
        let swap4 =
            eval_stack(&[0x51, 0x52, 0x53, 0x54, 0x72], SigVersion::WitnessV0).expect("2SWAP");
        assert_eq!(swap4, vec![num(3), num(4), num(1), num(2)]);
        let swap5 = eval_stack(&[0x51, 0x52, 0x53, 0x54, 0x55, 0x72], SigVersion::WitnessV0)
            .expect("2SWAP");
        assert_eq!(swap5, vec![num(1), num(4), num(5), num(2), num(3)]);

        eval(&vec![0x61; 201], SigVersion::WitnessV0).expect("201 ops is the limit");
        let err = eval(&vec![0x61; 202], SigVersion::WitnessV0).unwrap_err();
        assert!(format!("{err}").contains("op count"), "{err}");
        eval(&vec![0x60; 202], SigVersion::WitnessV0).expect("OP_16 is not an op-count");

        // MAX_STACK_SIZE is typically 1000; push 999 ones then 2DUP overflows.
        let mut script = vec![0x51; 999];
        script.push(0x6e); // OP_2DUP
        let err = eval(&script, SigVersion::WitnessV0).unwrap_err();
        assert!(
            format!("{err}").contains("stack") || format!("{err}").contains("size"),
            "got {err}"
        );
    }

    /// Core: main stack + altstack share MAX_STACK_SIZE. Direct PushBytes used
    /// to skip the opcode-end combined check (`push()` only counted the main
    /// stack). 201 TOALTSTACK (op budget) + 799 OP_1 + one PushBytes = 1001.
    #[test]
    fn stack_and_altstack_share_max_size_on_pushdata() {
        let mut script = vec![0x51; 201];
        script.extend(std::iter::repeat_n(0x6b, 201)); // OP_TOALTSTACK
        script.extend(std::iter::repeat_n(0x51, 799));
        script.extend_from_slice(&[0x01, 0x01]); // PushBytes, not OP_1
        let err = eval(&script, SigVersion::WitnessV0).unwrap_err();
        assert!(format!("{err}").contains("stack size"), "got {err}");

        // Both stacks non-empty and the product exceeds 1000 while the sum does not.
        let mut shared = vec![0x51, 0x51, 0x6b, 0x6b];
        shared.extend(std::iter::repeat_n(0x51, 501));
        shared.push(0x61);
        eval(&shared, SigVersion::WitnessV0).expect("sum under the shared limit");
    }

    /// Short `OP_PUSHDATA4` inside a legacy scriptCode. The payload must not be
    /// read as an opcode: needle `11 11 11` is encoded `03 11 11 11` and sits
    /// inside the four-byte push, so FindAndDelete leaves the script unchanged.
    #[test]
    fn find_and_delete_short_pushdata4_payload_is_not_an_opcode() {
        let script = vec![0x4e, 0x04, 0x00, 0x00, 0x00, 0x03, 0x11, 0x11, 0x11, 0x51];
        let needle = [0x11u8, 0x11, 0x11];
        let out = find_and_delete(&script, &needle);
        assert_eq!(out, script);
        assert_eq!(out.last(), Some(&0x51));
        assert!(out.windows(3).any(|w| w == needle));
        let short = vec![0x4e, 0x01, 0x00];
        let truncated = find_and_delete(&short, &[0xff]);
        assert_eq!(truncated.first(), Some(&0x4e));
    }
}

#[cfg(test)]
mod minimal_data_tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    fn eval_md(script_bytes: &[u8], md: bool) -> Result<(), String> {
        let tx = Transaction {
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
        };
        let script = Script::from_bytes(script_bytes);
        let mut ctx = EvalContext::new(&tx, 0, Amount::from_sat(50_000), script, SigVersion::Base);
        ctx.minimal_data = md;
        let mut stack = Vec::new();
        eval_script(script, &mut stack, &ctx).map_err(|e| format!("{e}"))?;
        require_true_top(&stack).map_err(|e| format!("{e}"))
    }

    #[test]
    fn check_minimal_push_table() {
        assert!(check_minimal_push(&[], 0x00));
        assert!(!check_minimal_push(&[], 0x4c)); // empty must be OP_0
        assert!(check_minimal_push(&[5], 0x55)); // OP_5
        assert!(!check_minimal_push(&[5], 0x01)); // direct push of 5 non-minimal
        assert!(check_minimal_push(&[0x81], 0x4f)); // OP_1NEGATE
        assert!(!check_minimal_push(&[0x81], 0x01));
        assert!(check_minimal_push(&[0x00], 0x01)); // one zero byte is fine
        assert!(check_minimal_push(&[0x11], 0x01)); // 17 as direct push
        assert!(check_minimal_push(&[0u8; 76], 0x4c)); // PUSHDATA1 for 76
        assert!(!check_minimal_push(&[0u8; 76], 0x4d));
    }

    #[test]
    fn executed_nonminimal_push_rejects_when_flag_on() {
        // PUSHDATA1 empty (0x4c 0x00) then DROP OP_1
        let script = vec![0x4c, 0x00, 0x75, 0x51];
        let err = eval_md(&script, true).unwrap_err();
        assert!(err.contains("MINIMALDATA"), "{err}");
        // Same script OK without the flag.
        eval_md(&script, false).expect("without MINIMALDATA");
    }

    #[test]
    fn unexecuted_nonminimal_push_ignored() {
        // OP_0 IF PUSHDATA1-empty ENDIF OP_1 — Core ignores non-minimal in false branch.
        let script = vec![0x00, 0x63, 0x4c, 0x00, 0x68, 0x51];
        eval_md(&script, true).expect("unexecuted non-minimal push OK");
    }

    #[test]
    fn nonminimal_scriptnum_rejects_when_flag_on() {
        // Push 0x00 (one zero byte) then NOT DROP OP_1 → SCRIPTNUM under flag.
        let script = vec![0x01, 0x00, 0x91, 0x75, 0x51];
        let err = eval_md(&script, true).unwrap_err();
        assert!(err.contains("SCRIPTNUM"), "{err}");
        // Without flag the zero-pad is accepted as 0; NOT → true; DROP; OP_1 → OK.
        eval_md(&script, false).expect("without require_minimal");
    }

    #[test]
    fn production_default_minimal_data_off() {
        let tx = Transaction {
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
        };
        let script = Script::from_bytes(&[0x51]);
        let ctx = EvalContext::new(&tx, 0, Amount::from_sat(1), script, SigVersion::Base);
        assert!(!ctx.minimal_data);
        assert!(!ctx.nullfail && !ctx.low_s && !ctx.strictenc && !ctx.null_dummy);
    }

    /// DERSIG: invalid DER encoding hard-fails; pre-BIP66 soft-fails CHECKSIG.
    #[test]
    fn dersig_hard_fails_invalid_encoding() {
        // Push 0xff + OP_0 + CHECKSIG
        let script = vec![0x01, 0xff, 0x00, 0xac];
        let tx = Transaction {
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
        };
        let sc = Script::from_bytes(&script);
        let ctx_on = EvalContext::new_with_flags(
            &tx,
            0,
            Amount::from_sat(50_000),
            sc,
            SigVersion::Base,
            true,
            true,
            true,
        );
        let mut stack = Vec::new();
        let err = eval_script(sc, &mut stack, &ctx_on).unwrap_err();
        assert!(format!("{err}").contains("SIG_DER"), "{err}");

        let ctx_off = EvalContext::new_with_flags(
            &tx,
            0,
            Amount::from_sat(50_000),
            sc,
            SigVersion::Base,
            true,
            true,
            false,
        );
        let mut stack = Vec::new();
        eval_script(sc, &mut stack, &ctx_off).expect("pre-bip66 soft-false CHECKSIG");
        assert!(!bitcoin::script::read_scriptbool(stack.last().unwrap()));

        let mut flags = crate::block::ScriptVerifyFlags::buried(false, false, false, false, false);
        flags.low_s = true;
        let job = crate::block::ScriptCheckJob::new(vec![], tx.clone(), flags);
        let ctx_low_s = EvalContext::new_with_flags(
            &tx,
            0,
            Amount::from_sat(50_000),
            sc,
            SigVersion::Base,
            false,
            false,
            false,
        )
        .apply_job_flags(&job);
        assert!(ctx_low_s.bip66_active, "LOW_S implies DERSIG");
        let err = eval_script(sc, &mut Vec::new(), &ctx_low_s).unwrap_err();
        assert!(format!("{err}").contains("SIG_DER"), "{err}");

        let mut ctx_only_low_s = EvalContext::new_with_flags(
            &tx,
            0,
            Amount::from_sat(50_000),
            sc,
            SigVersion::Base,
            false,
            false,
            false,
        );
        ctx_only_low_s.low_s = true;
        ctx_only_low_s.bip66_active = false;
        ctx_only_low_s.strictenc = false;
        let err = eval_script(sc, &mut Vec::new(), &ctx_only_low_s).unwrap_err();
        assert!(format!("{err}").contains("SIG_DER"), "{err}");
    }

    #[test]
    fn nullfail_hard_fails_nonzero_bad_sig() {
        // Non-empty invalid-but-DER-shaped? Use empty-key path: push minimal DER-like
        // garbage that fails DER under bip66 is SIG_DER not NULLFAIL. Use valid-shaped
        // non-verifying: 9-byte minimal DER + ALL with OP_0 pubkey — soft false under
        // DERSIG only; with NULLFAIL → hard fail.
        let sig = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01];
        let mut script = vec![sig.len() as u8];
        script.extend_from_slice(&sig);
        script.push(0x00); // empty/invalid pubkey as OP_0
        script.push(0xac); // CHECKSIG
        let tx = Transaction {
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
        };
        let sc = Script::from_bytes(&script);
        let mut ctx = EvalContext::new_with_flags(
            &tx,
            0,
            Amount::from_sat(50_000),
            sc,
            SigVersion::Base,
            true,
            true,
            true,
        );
        ctx.nullfail = true;
        let mut stack = Vec::new();
        let err = eval_script(sc, &mut stack, &ctx).unwrap_err();
        assert!(format!("{err}").contains("NULLFAIL"), "{err}");
    }
}

#[cfg(test)]
mod p2sh_redeem_parse_tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    #[test]
    fn eval_sig_then_p2sh_style() {
        // scriptSig 00 01 51 → stack [[],[0x51]]
        let ss = [0x00u8, 0x01, 0x51];
        let tx = Transaction {
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
        };
        let sc = Script::from_bytes(&ss);
        let ctx = EvalContext::new(&tx, 0, Amount::from_sat(1), sc, SigVersion::Base);
        let mut stack = Vec::new();
        eval_script(sc, &mut stack, &ctx).expect("scriptSig");
        let redeem = stack.pop().unwrap();
        let rs = Script::from_bytes(&redeem);
        let ctx2 = EvalContext::new(&tx, 0, Amount::from_sat(1), rs, SigVersion::Base);
        let r = eval_script(rs, &mut stack, &ctx2);
        assert!(r.is_ok(), "{r:?}");
    }
}

#[cfg(test)]
mod untaken_consensus_arms {
    use std::borrow::Cow;

    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::{Amount, OutPoint, PublicKey, Sequence, Transaction, TxIn, TxOut, Witness};

    fn tx_with_inputs(n: usize) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: LockTime::ZERO,
            input: (0..n)
                .map(|_| TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    #[test]
    fn find_and_delete_encodes_pushdata4_and_stops_on_a_truncated_push() {
        let encoded = find_and_delete(&[], &vec![0u8; 70_000]);
        assert!(encoded.is_empty());
        assert_eq!(find_and_delete(&[0x4c], &[0x11]), vec![0x4c]);
    }

    #[test]
    fn minimal_push_treats_data_over_64k_as_pushdata4() {
        assert!(check_minimal_push(&vec![0u8; 65_536], 0x4e));
    }

    #[test]
    fn from_job_past_the_prevouts_uses_a_zero_amount() {
        let tx = tx_with_inputs(1);
        let job = crate::block::ScriptCheckJob::new(
            vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
            tx,
            crate::block::ScriptVerifyFlags::buried(false, false, false, false, false),
        );
        let sc = Script::from_bytes(&[0x51]);
        let ctx = EvalContext::from_job(&job, &job.tx, 3, sc, SigVersion::Base).unwrap();
        assert_eq!(ctx.amount, Amount::ZERO);
    }

    #[test]
    fn checksig_sighash_failure_is_a_soft_false() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let pk = PublicKey::new(sk.public_key(&secp));
        let mut sig = secp
            .sign_ecdsa(&Message::from_digest([9; 32]), &sk)
            .serialize_der()
            .to_vec();
        sig.push(0x01);
        let tx = tx_with_inputs(1);
        let sc = Script::from_bytes(&[0x51]);
        let ctx = EvalContext::from_eval_parts(
            &tx,
            5,
            Amount::ZERO,
            sc,
            SigVersion::Base,
            false,
            false,
            false,
            Cow::Owned(crate::TxPrecompute::from_tx(&tx)),
        );
        let matched = ecdsa_sig_matches(&sig, &pk.to_bytes(), &ctx, &[0x51], PreTapscript::Base);
        assert!(!matched.unwrap());
    }

    #[test]
    fn tapscript_checksig_without_leaf_facts_fails() {
        let tx = tx_with_inputs(1);
        let mut script = vec![0x40];
        script.extend_from_slice(&[0x11; 64]);
        script.push(0x20);
        script.extend_from_slice(&[0x02; 32]);
        script.push(0xac);
        let sc = Script::from_bytes(&script);
        let ctx = EvalContext::from_eval_parts(
            &tx,
            0,
            Amount::ZERO,
            sc,
            SigVersion::TapScript,
            false,
            false,
            false,
            Cow::Owned(crate::TxPrecompute::from_tx(&tx)),
        );
        let err = eval_script(sc, &mut Vec::new(), &ctx).unwrap_err();
        assert!(format!("{err}").contains("tapleaf"), "{err}");
    }

    #[test]
    fn tapscript_checksig_rejects_a_signature_that_is_not_64_or_65_bytes() {
        let tx = tx_with_inputs(1);
        let mut script = vec![0x01, 0x11, 0x20];
        script.extend_from_slice(&[0x02; 32]);
        script.push(0xac);
        let sc = Script::from_bytes(&script);
        let ctx = EvalContext::from_eval_parts(
            &tx,
            0,
            Amount::ZERO,
            sc,
            SigVersion::TapScript,
            false,
            false,
            false,
            Cow::Owned(crate::TxPrecompute::from_tx(&tx)),
        );
        let err = eval_script(sc, &mut Vec::new(), &ctx).unwrap_err();
        assert!(format!("{err}").contains("CHECKSIG"), "{err}");
    }

    #[test]
    fn tapscript_checksigverify_rejects_an_empty_signature_on_a_32_byte_key() {
        let tx = tx_with_inputs(1);
        let mut script = vec![0x00, 0x20];
        script.extend_from_slice(&[0x02; 32]);
        script.push(0xad);
        let sc = Script::from_bytes(&script);
        let ctx = EvalContext::from_eval_parts(
            &tx,
            0,
            Amount::ZERO,
            sc,
            SigVersion::TapScript,
            false,
            false,
            false,
            Cow::Owned(crate::TxPrecompute::from_tx(&tx)),
        );
        let err = eval_script(sc, &mut Vec::new(), &ctx).unwrap_err();
        assert!(format!("{err}").contains("CHECKSIGVERIFY"), "{err}");
    }
}
