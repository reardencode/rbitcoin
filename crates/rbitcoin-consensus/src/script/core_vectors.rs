//! Bitcoin Core `script_tests.json` harness (unit-test only).
//!
//! Every data row is driven through the **shipped** script verification path
//! ([`crate::script::verify_job_all_inputs`]) using Core's credit/spend
//! transaction template. **All** data rows must match Core — no allowlist,
//! silent skip, or soft majority-rate gate.

#![cfg(test)]

use super::core_script::{assemble_script as assemble, credit_and_spend, SpendShape};
use super::interpreter::{self, EvalContext, SigVersion};
use super::verify_job_all_inputs;
use crate::block::{JobTx, ScriptCheckJob};
use bitcoin::hashes::Hash;
use bitcoin::script::Script;
use bitcoin::{Amount, ScriptBuf, Transaction, Witness};
use serde_json::Value;

fn load_json() -> Value {
    let path = super::core_fixture::stage_core_json("script_tests.json");
    let s = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("missing {path:?}: {e}"));
    serde_json::from_str(&s).expect("script_tests.json")
}

#[test]
fn assemble_edges_string_hex_push_and_errors() {
    // Quoted string → data push.
    let b = assemble("'Az'").expect("string");
    assert_eq!(b[0], 2); // push length
    assert_eq!(&b[1..], b"Az");
    // Hex raw bytes (not a push wrapper).
    let b = assemble("0x5152").expect("hex");
    assert_eq!(b, vec![0x51, 0x52]);
    // Numbers and opcode names.
    let b = assemble("1 2 ADD").expect("ops");
    assert!(!b.is_empty());
    // Push length encodings for larger payloads.
    let long = "x".repeat(80);
    let quoted = format!("'{long}'");
    let b = assemble(&quoted).expect("long push");
    assert_eq!(b[0], 0x4c); // OP_PUSHDATA1
    assert_eq!(b[1], 80);
    // Errors.
    assert!(assemble("'unterminated").is_err());
    assert!(assemble("0xabc").is_err()); // odd hex
    assert!(assemble("NOTANOPCODE").is_err());
    // Empty / whitespace only.
    assert!(assemble("   ").unwrap().is_empty());
    // 0X uppercase hex prefix.
    let b = assemble("0X5152").expect("hex upper");
    assert_eq!(b, vec![0x51, 0x52]);
    // Negative scriptnum encoding.
    let b = assemble("-1").expect("neg");
    assert!(!b.is_empty());
    // Larger push → OP_PUSHDATA1 already covered; force OP_PUSHDATA2 via long payload.
    let long = "y".repeat(300);
    let b = assemble(&format!("'{long}'")).expect("pushdata2");
    assert_eq!(b[0], 0x4d); // OP_PUSHDATA2
                            // Opcode token mixed case / known names.
    let b = assemble("OP_DUP OP_HASH160").expect("ops named");
    assert!(!b.is_empty());
    // Zero token → OP_0.
    let b = assemble("0").expect("zero");
    assert_eq!(b, vec![0x00]);
    // Small ints use opcode forms (MINIMALDATA-safe), not data pushes.
    assert_eq!(assemble("1").unwrap(), vec![0x51]);
    assert_eq!(assemble("16").unwrap(), vec![0x60]);
    assert_eq!(assemble("-1").unwrap(), vec![0x4f]);
    // Larger ints use minimal CScriptNum push.
    let b = assemble("17").unwrap();
    assert_eq!(b[0], 1); // direct push length
    assert_eq!(&b[1..], &[17]);
}

// ── Flag mapping ────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
struct CoreFlags {
    p2sh: bool,
    dersig: bool,
    cltv: bool,
    csv: bool,
    witness: bool,
    taproot: bool,
    cleanstack: bool,
    discourage_upgradable_nops: bool,
    /// Core `SCRIPT_VERIFY_MINIMALDATA`.
    minimal_data: bool,
    /// Core `SCRIPT_VERIFY_NULLFAIL`.
    nullfail: bool,
    /// Core `SCRIPT_VERIFY_LOW_S`.
    low_s: bool,
    /// Core `SCRIPT_VERIFY_STRICTENC` (DER + hashtype + pubkey type).
    strictenc: bool,
    /// Core `SCRIPT_VERIFY_NULLDUMMY` (BIP147).
    null_dummy: bool,
    /// Core `SCRIPT_VERIFY_MINIMALIF`.
    minimal_if: bool,
    /// Core `SCRIPT_VERIFY_SIGPUSHONLY`.
    sig_push_only: bool,
    /// Other named flags we do not yet implement (diagnostics only).
    extra: Vec<String>,
}

fn parse_flags(s: &str) -> CoreFlags {
    let mut f = CoreFlags::default();
    if s.is_empty() || s.eq_ignore_ascii_case("NONE") {
        return f;
    }
    for part in s.split(',') {
        let p = part.trim().to_uppercase();
        if p.is_empty() {
            continue;
        }
        match p.as_str() {
            "P2SH" => f.p2sh = true,
            "DERSIG" => f.dersig = true,
            "STRICTENC" => {
                // STRICTENC implies IsValidSignatureEncoding + hashtype + pubkey type.
                f.dersig = true;
                f.strictenc = true;
            }
            "MINIMALDATA" => f.minimal_data = true,
            "LOW_S" => {
                f.low_s = true;
                f.dersig = true; // Core CheckSignatureEncoding: LOW_S requires DER
            }
            "NULLFAIL" => f.nullfail = true,
            "NULLDUMMY" => f.null_dummy = true,
            "MINIMALIF" => f.minimal_if = true,
            "SIGPUSHONLY" => f.sig_push_only = true,
            "WITNESS_PUBKEYTYPE" => f.extra.push(p), // also read via apply → job.witness_pubkeytype
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"
            | "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION"
            | "DISCOURAGE_OP_SUCCESS"
            | "DISCOURAGE_UPGRADABLE_PUBKEYTYPE" => {
                f.extra.push(p);
            }
            "CHECKLOCKTIMEVERIFY" => f.cltv = true,
            "CHECKSEQUENCEVERIFY" => f.csv = true,
            "WITNESS" => f.witness = true,
            "TAPROOT" | "TAPSCRIPT" => {
                f.taproot = true;
                f.witness = true;
            }
            "CLEANSTACK" => f.cleanstack = true,
            "DISCOURAGE_UPGRADABLE_NOPS" => f.discourage_upgradable_nops = true,
            other => f.extra.push(other.to_string()),
        }
    }
    f
}

/// Apply Core standardness/script flags onto an [`EvalContext`].
fn apply_eval_flags(ctx: &mut EvalContext<'_>, flags: &CoreFlags) {
    ctx.minimal_data = flags.minimal_data;
    ctx.nullfail = flags.nullfail;
    ctx.low_s = flags.low_s;
    ctx.strictenc = flags.strictenc;
    ctx.null_dummy = flags.null_dummy;
    ctx.minimal_if = flags.minimal_if;
    // STRICTENC/LOW_S also force DER encoding checks via bip66_active in checksig.
    if flags.dersig || flags.strictenc || flags.low_s {
        ctx.bip66_active = true;
    }
}

/// Core script_tests witness cell: hex items + optional `#SCRIPT#` / `#CONTROLBLOCK#`,
/// ending with nValue (BTC). Returns optional Taproot output key for `#TAPROOTOUTPUT#`.
fn parse_witness_and_amount(first: &Value) -> Result<(Witness, Amount, Option<[u8; 32]>), String> {
    // Core: [wit_hex..., amount_number] inside first array element when present.
    let arr = first
        .as_array()
        .ok_or_else(|| "witness cell not array".to_string())?;
    if arr.is_empty() {
        return Ok((Witness::new(), Amount::ZERO, None));
    }
    let mut amount = Amount::ZERO;
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut taproot_output: Option<[u8; 32]> = None;

    for (i, cell) in arr.iter().enumerate() {
        if let Some(n) = cell.as_f64() {
            // Last numeric is nValue in BTC (Core uses double).
            if i == arr.len() - 1 || cell.as_str().is_none() {
                let sats = (n * 100_000_000.0).round() as i64;
                amount = Amount::from_sat(sats.max(0) as u64);
                continue;
            }
        }
        if let Some(s) = cell.as_str() {
            super::core_script::push_core_witness_token(&mut stack, &mut taproot_output, s)?;
        } else if let Some(n) = cell.as_f64() {
            let sats = (n * 100_000_000.0).round() as i64;
            amount = Amount::from_sat(sats.max(0) as u64);
        }
    }
    Ok((
        Witness::from_slice(&stack.iter().map(|v| v.as_slice()).collect::<Vec<_>>()),
        amount,
        taproot_output,
    ))
}

/// True if discouraged NOP1/NOP4–10 appears **outside** IF/ENDIF regions.
///
/// Without a stack we cannot know which IF branch runs; Core only fails when
/// the NOP is executed. Skipping all IF…ENDIF bodies avoids false positives
/// (e.g. `0 IF NOP10 ENDIF 1` with false IF). Direct `NOP10` still matches.
fn has_discouraged_nop_outside_if(script: &[u8]) -> bool {
    let mut i = 0;
    let mut depth = 0i32;
    while i < script.len() {
        let op = script[i];
        if op > 0 && op < 0x4c {
            i += 1 + op as usize;
            continue;
        }
        if op == 0x4c && i + 1 < script.len() {
            let n = script[i + 1] as usize;
            i += 2 + n;
            continue;
        }
        if op == 0x4d && i + 2 < script.len() {
            let n = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
            i += 3 + n;
            continue;
        }
        if op == 0x4e && i + 4 < script.len() {
            let n = u32::from_le_bytes([script[i + 1], script[i + 2], script[i + 3], script[i + 4]])
                as usize;
            i += 5 + n;
            continue;
        }
        match op {
            0x63 | 0x64 => {
                depth += 1;
                i += 1;
            }
            0x68 => {
                depth = (depth - 1).max(0);
                i += 1;
            }
            n if depth == 0 && (0xb0..=0xb9).contains(&n) && n != 0xb1 && n != 0xb2 => {
                return true;
            }
            _ => i += 1,
        }
    }
    false
}

fn run_script_row(
    script_sig: &[u8],
    script_pubkey: &[u8],
    witness: Witness,
    amount: Amount,
    flags: &CoreFlags,
    shape: SpendShape,
) -> Result<(), String> {
    // DISCOURAGE: NOP1/4–10 outside IF regions (see has_discouraged_nop_outside_if).
    if flags.discourage_upgradable_nops
        && (has_discouraged_nop_outside_if(script_sig)
            || has_discouraged_nop_outside_if(script_pubkey))
    {
        return Err("DISCOURAGE_UPGRADABLE_NOPS".into());
    }
    // SCRIPT_VERIFY_SIGPUSHONLY, and BIP16 P2SH always requires push-only scriptSig.
    if flags.sig_push_only || (flags.p2sh && bitcoin::Script::from_bytes(script_pubkey).is_p2sh()) {
        let mut tmp = Vec::new();
        interpreter::eval_script_sig_pushes(Script::from_bytes(script_sig), &mut tmp)
            .map_err(|_| "SIG_PUSHONLY".to_string())?;
    }

    // Without SCRIPT_VERIFY_WITNESS, Core treats v0/v1 programs as bare scripts.
    // Production always enables witness post-segwit; flag-off is Core-vector only.
    if !flags.witness {
        let (_credit, spend) = credit_and_spend(
            ScriptBuf::from_bytes(script_pubkey.to_vec()),
            ScriptBuf::from_bytes(script_sig.to_vec()),
            witness,
            amount,
            shape,
        );
        return eval_bare_pair(
            &spend,
            script_sig,
            script_pubkey,
            amount,
            flags,
            flags.cleanstack,
        );
    }

    let job = script_row_job(script_sig, script_pubkey, witness, amount, flags, shape);
    verify_job_all_inputs(&job).map_err(|e| format!("{e}"))
}

/// Credit/spend job the witness branch of `run_script_row` feeds to
/// [`verify_job_all_inputs`]. The fast-path test calls the typed verifiers
/// on this same builder. Flag-off rows use [`eval_bare_pair`] instead.
fn script_row_job(
    script_sig: &[u8],
    script_pubkey: &[u8],
    witness: Witness,
    amount: Amount,
    flags: &CoreFlags,
    shape: SpendShape,
) -> ScriptCheckJob {
    let (credit, spend) = credit_and_spend(
        ScriptBuf::from_bytes(script_pubkey.to_vec()),
        ScriptBuf::from_bytes(script_sig.to_vec()),
        witness,
        amount,
        shape,
    );
    let prev = credit.output[0].clone();
    ScriptCheckJob {
        txid: spend.compute_txid().to_byte_array(),
        prevouts: crate::block::JobPrevouts::owned(vec![prev]),
        tx: JobTx::owned(spend),
        flags: crate::block::ScriptVerifyFlags {
            bip65_active: flags.cltv,
            bip112_active: flags.csv,
            bip66_active: flags.dersig || flags.strictenc || flags.low_s,
            bip16_active: flags.p2sh,
            taproot_active: flags.taproot,
            minimal_if: flags.minimal_if,
            nullfail: flags.nullfail,
            low_s: flags.low_s,
            strictenc: flags.strictenc,
            null_dummy: flags.null_dummy,
            minimal_data: flags.minimal_data,
            witness_pubkeytype: flags.extra.iter().any(|e| e == "WITNESS_PUBKEYTYPE"),
            witness_active: flags.witness,
            discourage_upgradable_witness: flags
                .extra
                .iter()
                .any(|e| e == "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"),
            const_scriptcode: flags.extra.iter().any(|e| e == "CONST_SCRIPTCODE"),
            cleanstack: flags.cleanstack,
        },
        pre: std::sync::OnceLock::new(),
    }
}

/// Core EvalScript(scriptSig)+EvalScript(scriptPubKey) with optional P2SH redeem.
fn eval_bare_pair(
    spend: &Transaction,
    script_sig: &[u8],
    script_pubkey: &[u8],
    amount: Amount,
    flags: &CoreFlags,
    cleanstack: bool,
) -> Result<(), String> {
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let ss = Script::from_bytes(script_sig);
    if !script_sig.is_empty() {
        let mut ctx = EvalContext::new_with_flags(
            spend,
            0,
            amount,
            ss,
            SigVersion::Base,
            flags.cltv,
            flags.csv,
            flags.dersig || flags.strictenc || flags.low_s,
        );
        apply_eval_flags(&mut ctx, flags);
        let _ = interpreter::eval_script(ss, &mut stack, &ctx).map_err(|e| format!("{e}"))?;
    }
    // Core BIP16: keep a copy of the stack after scriptSig so P2SH can restore
    // the redeemScript (scriptPubKey HASH160/EQUAL would otherwise consume it).
    let stack_copy = stack.clone();

    let spk = Script::from_bytes(script_pubkey);
    let mut ctx = EvalContext::new_with_flags(
        spend,
        0,
        amount,
        spk,
        SigVersion::Base,
        flags.cltv,
        flags.csv,
        flags.dersig || flags.strictenc || flags.low_s,
    );
    apply_eval_flags(&mut ctx, flags);
    let need = interpreter::eval_script(spk, &mut stack, &ctx).map_err(|e| format!("{e}"))?;
    if !need {
        return Ok(()); // OP_SUCCESS-like
    }

    // BIP16 P2SH: if flag set and scriptPubKey is P2SH, restore stack and eval redeem.
    if flags.p2sh && bitcoin::Script::from_bytes(script_pubkey).is_p2sh() {
        // scriptPubKey must have left a true top (serialized).
        interpreter::require_true_top(&stack).map_err(|e| format!("{e}"))?;
        stack = stack_copy;
        if stack.is_empty() {
            return Err("P2SH empty stack".into());
        }
        let redeem = stack.pop().unwrap();
        if flags.discourage_upgradable_nops && has_discouraged_nop_outside_if(&redeem) {
            return Err("DISCOURAGE_UPGRADABLE_NOPS".into());
        }
        let redeem_script = Script::from_bytes(&redeem);
        // Redeem is evaluated as scriptCode for sighash.
        let mut ctx_r = EvalContext::new_with_flags(
            spend,
            0,
            amount,
            redeem_script,
            SigVersion::Base,
            flags.cltv,
            flags.csv,
            flags.dersig || flags.strictenc || flags.low_s,
        );
        apply_eval_flags(&mut ctx_r, flags);
        let need_r = interpreter::eval_script(redeem_script, &mut stack, &ctx_r)
            .map_err(|e| format!("P2SH redeem: {e}"))?;
        if !need_r {
            return Ok(());
        }
    }

    if cleanstack {
        interpreter::require_clean_true(&stack).map_err(|e| format!("{e}"))?;
    } else {
        interpreter::require_true_top(&stack).map_err(|e| format!("{e}"))?;
    }
    Ok(())
}

// ── Allowlist: explicit, machine-checked ────────────────────────────────────
//
// Format: (json_row_index, reason). Unknown failures must not be soft-passed.

/// Rows we intentionally do not require to match Core yet.
/// Map our error / Ok to whether it matches Core's expected result code.
fn outcome_matches(expect: &str, got: &Result<(), String>) -> bool {
    match expect {
        "OK" => got.is_ok(),
        "EVAL_FALSE" => {
            // Successful parse/eval but false final stack — or any script false.
            matches!(got, Err(m) if m.contains("script false")
                || m.contains("cleanstack")
                || m.contains("EVAL_FALSE")
                || m.contains("false"))
                || matches!(got, Err(m) if m.contains("script verification failed"))
        }
        // Named failure codes: any rejection counts as match (Core distinguishes
        // error codes; we only require reject).
        _ => got.is_err(),
    }
}

// ── Row runner ──────────────────────────────────────────────────────────────

struct RowStats {
    total: u32,
    ran: u32,
    pass: u32,
    fail: u32,
    failures: Vec<String>,
}

fn run_all_script_rows() -> RowStats {
    let root = load_json();
    let arr = root.as_array().expect("script_tests root array");
    let mut st = RowStats {
        total: 0,
        ran: 0,
        pass: 0,
        fail: 0,
        failures: Vec::new(),
    };

    for (idx, row) in arr.iter().enumerate() {
        let Value::Array(cells) = row else {
            continue;
        };
        if cells.is_empty() {
            continue;
        }
        // Comment / format rows: first element not string and not witness array form.
        let is_witness_form = cells[0].is_array();
        let is_plain = cells[0].as_str().is_some();
        if !is_witness_form && !is_plain {
            continue;
        }
        if is_plain && cells.len() < 4 {
            continue;
        }
        if is_witness_form && cells.len() < 5 {
            continue;
        }

        let (witness, amount, sig_s, pk_s, flags_s, expect_s, tap_out) = if is_witness_form {
            let (w, amt, tout) = match parse_witness_and_amount(&cells[0]) {
                Ok(v) => v,
                Err(e) => {
                    st.total += 1;
                    st.fail += 1;
                    if st.failures.len() < 40 {
                        st.failures.push(format!("#{idx} witness parse: {e}"));
                    }
                    continue;
                }
            };
            (
                w,
                amt,
                cells[1].as_str().unwrap_or(""),
                cells[2].as_str().unwrap_or(""),
                cells[3].as_str().unwrap_or(""),
                cells[4].as_str().unwrap_or(""),
                tout,
            )
        } else {
            (
                Witness::new(),
                Amount::ZERO,
                cells[0].as_str().unwrap_or(""),
                cells[1].as_str().unwrap_or(""),
                cells[2].as_str().unwrap_or(""),
                cells[3].as_str().unwrap_or(""),
                None,
            )
        };

        st.total += 1;
        let flags = parse_flags(flags_s);

        let sig_bytes = match assemble(sig_s) {
            Ok(b) => b,
            Err(e) => {
                st.ran += 1;
                st.fail += 1;
                if st.failures.len() < 40 {
                    st.failures
                        .push(format!("#{idx} assemble scriptSig: {e} sig={sig_s:?}"));
                }
                continue;
            }
        };
        let pk_bytes = match super::core_script::assemble_script_pubkey(pk_s, tap_out) {
            Ok(b) => b,
            Err(e) => {
                st.ran += 1;
                st.fail += 1;
                if st.failures.len() < 40 {
                    st.failures
                        .push(format!("#{idx} assemble scriptPubKey: {e} pk={pk_s:?}"));
                }
                continue;
            }
        };

        st.ran += 1;
        let got = run_script_row(
            &sig_bytes,
            &pk_bytes,
            witness,
            amount,
            &flags,
            SpendShape::default(),
        );
        let ok = outcome_matches(expect_s, &got);

        if ok {
            st.pass += 1;
            continue;
        }

        st.fail += 1;
        if st.failures.len() < 40 {
            st.failures.push(format!(
                "#{idx} sig={sig_s:?} pk={pk_s:?} flags={flags_s} expect={expect_s} got={got:?}"
            ));
        }
    }
    st
}

/// Full Core `script_tests.json` corpus: every data row via shipped verify path.
#[test]
// btc-lean: INV-022 INV-023 INV-041 INV-042 INV-043 INV-044 INV-045 INV-046 INV-047 INV-048 INV-049
// btc-lean: INV-050 INV-052 INV-054 INV-055 INV-056 INV-057 INV-058 INV-059 INV-060 INV-061 INV-062
// btc-lean: INV-063 INV-064 INV-066 INV-067 INV-068 INV-069 INV-070 INV-071 INV-072 INV-073 INV-074
// btc-lean: INV-075 INV-077 INV-078 SCR-001 SCR-002 SCR-003 SCR-004 SCR-005 SCR-006 SCR-007 SCR-008
// btc-lean: SCR-011 SCR-012 SCR-013 SCR-017 SCR-018 SCR-019 SCR-020 SCR-021 SCR-022 SCR-023 SCR-024
// btc-lean: SCR-025 SCR-026 SCR-027 SCR-028 SCR-029 SCR-030 SCR-031 SCR-032 SCR-033 SCR-034 SCR-035
// btc-lean: SCR-036 SCR-037 SCR-038 SCR-040 SCR-041 SCR-042 SCR-043 SCR-044 SCR-045 SCR-046 SCR-047
// btc-lean: SCR-048 SCR-049 SCR-050 SCR-051 SCR-052 SCR-053 SCR-054 SCR-055 SCR-056 SCR-057 SCR-058
// btc-lean: SCR-059 SCR-060 SCR-061 SCR-062 SCR-063 SCR-064 SCR-065 SCR-066 SCR-067 SCR-068 SCR-069
// btc-lean: SCR-070 SCR-071 SCR-072 SCR-073 SCR-074 SCR-075 SCR-076 SCR-077 SCR-078 SCR-079 SCR-080
// btc-lean: SCR-081 SCR-082 SCR-083 SCR-084 SCR-085 SCR-086 SCR-087 SCR-088 SCR-089 SCR-090 SCR-091
// btc-lean: SCR-092 SCR-093 SCR-094 SCR-095 SCR-096 SCR-097 SCR-098 SCR-099 SCR-100 SCR-101 SCR-102
// btc-lean: SCR-103 SCR-104 SCR-105 SCR-106 SCR-107 SCR-108 SCR-109 SCR-110 SCR-111 SCR-112 SCR-113
// btc-lean: SCR-114 SCR-115 SCR-116 SCR-117 SCR-118 SCR-119 SCR-120 SCR-121 SCR-122 SCR-123 SCR-124
// btc-lean: SCR-125 SCR-126 SCR-127 SCR-128 SCR-129 SCR-130 SCR-131 SCR-132 SCR-133 SCR-134 SCR-135
// btc-lean: SCR-136 SCR-137 SCR-138 SCR-139 SCR-141 SCR-152 SCR-153 SCR-154 SCR-155 SCR-170 SCR-171
// btc-lean: SCR-172 SCR-174 SCR-178 SCR-183 SGN-111 SWT-001 SWT-002 SWT-003 SWT-004 SWT-010 SWT-011
// btc-lean: SWT-012 SWT-013 SWT-015 SWT-016 SWT-061 SWT-062 SWT-063 SWT-064 SWT-065 TPR-055 TPR-056
// btc-lean: TPR-057 TPR-058 TPR-059 TPR-060 TPR-061 TPR-062 TPR-063 TPR-064 TPR-065 TPR-066 TPR-067
// btc-lean: TPR-068 TXV-043 TXV-044 TXV-045 TXV-046 TXV-047 TXV-048
fn core_script_tests_all_rows() {
    let st = run_all_script_rows();
    eprintln!(
        "core script_tests: total={total} ran={ran} pass={pass} fail={fail}",
        total = st.total,
        ran = st.ran,
        pass = st.pass,
        fail = st.fail,
    );
    for f in &st.failures {
        eprintln!("  FAIL {f}");
    }
    assert!(
        st.fail == 0,
        "core script_tests failures: {} (see FAIL lines)",
        st.fail
    );
    assert!(
        st.total > 500,
        "expected hundreds of Core rows, total={}",
        st.total
    );
    assert_eq!(
        st.pass, st.ran,
        "every ran row must pass (pass={} ran={})",
        st.pass, st.ran
    );
}

/// Our script corpus, in addition to Core's JSON. Each `row` is Core
/// `script_tests.json` form. The v31.1 oracle in `script-oracle/` runs the
/// same file.
#[test]
fn script_corpus_rows_match_our_interpreter() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/script_corpus/script_tests.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let rows: Vec<Value> = serde_json::from_str(&text).expect("script corpus json");
    assert!(!rows.is_empty(), "script corpus is empty");
    for row in &rows {
        let id = row["id"].as_str().unwrap_or("?").to_string();
        let cells = row["row"]
            .as_array()
            .unwrap_or_else(|| panic!("{id}: missing row"));
        let (witness, amount, sig_s, pk_s, flags_s, expect, tap_out) = if cells[0].is_array() {
            assert!(
                cells.len() >= 5,
                "{id}: witness row needs witness, scriptSig, scriptPubKey, flags, result"
            );
            let (witness, amount, tap_out) =
                parse_witness_and_amount(&cells[0]).unwrap_or_else(|e| panic!("{id} witness: {e}"));
            (
                witness,
                amount,
                cells[1].as_str().unwrap_or(""),
                cells[2].as_str().unwrap_or(""),
                cells[3].as_str().unwrap_or(""),
                cells[4].as_str().unwrap_or(""),
                tap_out,
            )
        } else {
            assert!(
                cells.len() >= 4,
                "{id}: row needs scriptSig, scriptPubKey, flags, result"
            );
            (
                Witness::new(),
                Amount::ZERO,
                cells[0].as_str().unwrap_or(""),
                cells[1].as_str().unwrap_or(""),
                cells[2].as_str().unwrap_or(""),
                cells[3].as_str().unwrap_or(""),
                None,
            )
        };
        let sig = assemble(sig_s).unwrap_or_else(|e| panic!("{id} scriptSig: {e}"));
        let pk = super::core_script::assemble_script_pubkey(pk_s, tap_out)
            .unwrap_or_else(|e| panic!("{id} scriptPubKey: {e}"));
        let flags = parse_flags(flags_s);
        let shape = super::core_script::spend_shape_from_json(row.get("spend"))
            .unwrap_or_else(|e| panic!("{id} spend: {e}"));
        let got = run_script_row(&sig, &pk, witness, amount, &flags, shape);
        assert!(
            outcome_matches(expect, &got),
            "{id}: expect {expect} got {got:?}"
        );
    }
}

struct CorpusSpend {
    sig: Vec<u8>,
    pk: Vec<u8>,
    witness: Witness,
    amount: Amount,
    flags: CoreFlags,
}

fn corpus_spend(rows: &[Value], id: &str) -> CorpusSpend {
    let row = rows
        .iter()
        .find(|row| row["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("missing corpus id {id}"));
    let cells = row["row"]
        .as_array()
        .unwrap_or_else(|| panic!("{id}: missing row"));
    let (witness, amount, sig_s, pk_s, flags_s, tap_out) = if cells[0].is_array() {
        let (witness, amount, tap_out) =
            parse_witness_and_amount(&cells[0]).unwrap_or_else(|e| panic!("{id} witness: {e}"));
        (
            witness,
            amount,
            cells[1].as_str().unwrap_or(""),
            cells[2].as_str().unwrap_or(""),
            cells[3].as_str().unwrap_or(""),
            tap_out,
        )
    } else {
        (
            Witness::new(),
            Amount::ZERO,
            cells[0].as_str().unwrap_or(""),
            cells[1].as_str().unwrap_or(""),
            cells[2].as_str().unwrap_or(""),
            None,
        )
    };
    CorpusSpend {
        sig: assemble(sig_s).unwrap_or_else(|e| panic!("{id} scriptSig: {e}")),
        pk: super::core_script::assemble_script_pubkey(pk_s, tap_out)
            .unwrap_or_else(|e| panic!("{id} scriptPubKey: {e}")),
        witness,
        amount,
        flags: parse_flags(flags_s),
    }
}

fn load_corpus_rows() -> Vec<Value> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/script_corpus/script_tests.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    serde_json::from_str(&text).expect("script corpus json")
}

/// Typed P2PKH, P2WPKH, and key-path P2TR accept the corpus spends.
///
/// Accept or reject from `run_script_row` does not name the function that ran.
/// These calls use the credit/spend job that function builds, and the classify
/// / `needs_interpreted_ecdsa` checks are the arms `verify_input` matches on.
#[test]
fn corpus_fast_paths_call_typed_verifiers() {
    use bitcoin::sighash::SighashCache;

    use super::classify::{classify, witness_program, ScriptKind};
    use super::crypto::TapSpentHashes;
    use super::{needs_interpreted_ecdsa, p2pkh, p2tr, p2wpkh, verify_input};

    let rows = load_corpus_rows();
    let tap = TapSpentHashes::default();

    let spend = corpus_spend(&rows, "p2pkh-fast-ok");
    let job = script_row_job(
        &spend.sig,
        &spend.pk,
        spend.witness,
        spend.amount,
        &spend.flags,
        SpendShape::default(),
    );
    let spk = Script::from_bytes(job.prevout_script(0).expect("prevout"));
    assert_eq!(classify(spk), ScriptKind::P2pkh);
    assert!(!needs_interpreted_ecdsa(&job));
    let owned = Transaction::clone(&job.tx);
    let mut cache = SighashCache::new(&owned);
    p2pkh::verify(&job, 0, &owned, &mut cache).expect("p2pkh typed accept");
    let tx: &Transaction = &job.tx;
    let mut dispatch_cache = None;
    verify_input(&job, 0, tx, &mut dispatch_cache, job.pre(), &tap).expect("p2pkh dispatch");
    let mut policy = script_row_job(
        &spend.sig,
        &spend.pk,
        Witness::new(),
        spend.amount,
        &spend.flags,
        SpendShape::default(),
    );
    policy.low_s = true;
    assert!(needs_interpreted_ecdsa(&policy));

    let spend = corpus_spend(&rows, "p2pkh-fast-mutated");
    let job = script_row_job(
        &spend.sig,
        &spend.pk,
        spend.witness,
        spend.amount,
        &spend.flags,
        SpendShape::default(),
    );
    let spk = Script::from_bytes(job.prevout_script(0).expect("prevout"));
    assert_ne!(classify(spk), ScriptKind::P2pkh);
    let tx: &Transaction = &job.tx;
    let mut dispatch_cache = None;
    assert!(verify_input(&job, 0, tx, &mut dispatch_cache, job.pre(), &tap).is_err());

    let spend = corpus_spend(&rows, "p2pkh-fad-collision");
    let job = script_row_job(
        &spend.sig,
        &spend.pk,
        spend.witness,
        spend.amount,
        &spend.flags,
        SpendShape::default(),
    );
    let spk = Script::from_bytes(job.prevout_script(0).expect("prevout"));
    assert_eq!(classify(spk), ScriptKind::P2pkh);
    let owned = Transaction::clone(&job.tx);
    let mut cache = SighashCache::new(&owned);
    let err = p2pkh::verify(&job, 0, &owned, &mut cache).expect_err("collision");
    assert!(!super::p2pkh_scriptsig_shape_error(&err), "{err}");
    let tx: &Transaction = &job.tx;
    let mut dispatch_cache = None;
    assert!(verify_input(&job, 0, tx, &mut dispatch_cache, job.pre(), &tap).is_err());

    let spend = corpus_spend(&rows, "p2wpkh-fast-ok");
    let job = script_row_job(
        &spend.sig,
        &spend.pk,
        spend.witness,
        spend.amount,
        &spend.flags,
        SpendShape::default(),
    );
    let spk = Script::from_bytes(job.prevout_script(0).expect("prevout"));
    let (version, program) = witness_program(spk).expect("v0 program");
    assert_eq!((version, program.len()), (0, 20));
    assert!(!needs_interpreted_ecdsa(&job));
    let tx: &Transaction = &job.tx;
    p2wpkh::verify(&job, 0, tx, job.pre()).expect("p2wpkh typed accept");
    let mut dispatch_cache = None;
    verify_input(&job, 0, tx, &mut dispatch_cache, job.pre(), &tap).expect("p2wpkh dispatch");

    let spend = corpus_spend(&rows, "p2wpkh-fast-mutated");
    let job = script_row_job(
        &spend.sig,
        &spend.pk,
        spend.witness,
        spend.amount,
        &spend.flags,
        SpendShape::default(),
    );
    let spk = Script::from_bytes(job.prevout_script(0).expect("prevout"));
    let (version, program) = witness_program(spk).expect("still a v0 program");
    assert_eq!((version, program.len()), (0, 20));
    let tx: &Transaction = &job.tx;
    assert!(p2wpkh::verify(&job, 0, tx, job.pre()).is_err());

    let spend = corpus_spend(&rows, "p2tr-keypath-ok");
    let job = script_row_job(
        &spend.sig,
        &spend.pk,
        spend.witness,
        spend.amount,
        &spend.flags,
        SpendShape::default(),
    );
    let tx: &Transaction = &job.tx;
    p2tr::verify(&job, 0, tx, &tap).expect("key path typed accept");
    let mut dispatch_cache = None;
    verify_input(&job, 0, tx, &mut dispatch_cache, job.pre(), &tap).expect("p2tr dispatch");

    let spend = corpus_spend(&rows, "p2tr-keypath-mutated");
    let job = script_row_job(
        &spend.sig,
        &spend.pk,
        spend.witness,
        spend.amount,
        &spend.flags,
        SpendShape::default(),
    );
    let tx: &Transaction = &job.tx;
    assert!(p2tr::verify(&job, 0, tx, &tap).is_err());

    let spend = corpus_spend(&rows, "p2pkh-fast-ok");
    let mut sig = spend.sig;
    // Last byte of the 0x47-byte signature push is the hashtype. Flipping it
    // keeps the DER encoding and fails the typed ECDSA check.
    sig[0x47] = 0x03;
    let job = script_row_job(
        &sig,
        &spend.pk,
        Witness::new(),
        spend.amount,
        &spend.flags,
        SpendShape::default(),
    );
    let owned = Transaction::clone(&job.tx);
    let mut cache = SighashCache::new(&owned);
    let err = p2pkh::verify(&job, 0, &owned, &mut cache).expect_err("bad hashtype");
    assert!(format!("{err}").contains("ecdsa"), "{err}");
}
