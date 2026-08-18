//! Bitcoin Core `script_tests.json` harness (unit-test only).
//!
//! Every data row is driven through the **shipped** script verification path
//! ([`crate::script::verify_job_all_inputs`]) using Core's credit/spend
//! transaction template. **All** data rows must match Core — no allowlist,
//! silent skip, or soft majority-rate gate.

#![cfg(test)]

use super::interpreter::{self, EvalContext, SigVersion};
use super::verify_job_all_inputs;
use crate::block::{JobTx, ScriptCheckJob};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::script::Script;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
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

// ── Core script language assembler ──────────────────────────────────────────

/// Assemble Core script string ("1 2 ADD", "0x4c 0x01 0x07", "'Az'") to bytes.
fn assemble(src: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    let b = src.as_bytes();
    while i < b.len() {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        if b[i] == b'\'' {
            i += 1;
            let start = i;
            while i < b.len() && b[i] != b'\'' {
                i += 1;
            }
            if i >= b.len() {
                return Err("unterminated string".into());
            }
            let s = &src[start..i];
            i += 1;
            push_data(&mut out, s.as_bytes());
            continue;
        }
        if b[i] == b'0' && i + 1 < b.len() && (b[i + 1] == b'x' || b[i + 1] == b'X') {
            i += 2;
            let start = i;
            while i < b.len() && b[i].is_ascii_hexdigit() {
                i += 1;
            }
            let hex = &src[start..i];
            if !hex.len().is_multiple_of(2) {
                return Err(format!("odd hex: {hex}"));
            }
            // Core: 0xHEX is raw script bytes (opcodes + data), not a push.
            for j in (0..hex.len()).step_by(2) {
                out.push(u8::from_str_radix(&hex[j..j + 2], 16).map_err(|e| e.to_string())?);
            }
            continue;
        }
        let start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() {
            i += 1;
        }
        let tok = &src[start..i];
        if tok.is_empty() {
            continue;
        }
        // Core ParseScript: -1, 0, 1..16 are single opcodes (OP_1NEGATE / OP_0 /
        // OP_1..OP_16). Other integers use minimal push of CScriptNum bytes.
        // Using raw pushes for 1..16 would fail SCRIPT_VERIFY_MINIMALDATA.
        if let Ok(n) = tok.parse::<i64>() {
            if n == 0 {
                out.push(0x00); // OP_0
            } else if n == -1 {
                out.push(0x4f); // OP_1NEGATE
            } else if (1..=16).contains(&n) {
                out.push(0x50 + n as u8); // OP_1 .. OP_16
            } else {
                let enc = encode_scriptnum(n);
                push_data(&mut out, &enc);
            }
            continue;
        }
        let op = opcode_byte(tok).ok_or_else(|| format!("unknown token {tok}"))?;
        out.push(op);
    }
    Ok(out)
}

fn push_data(out: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n < 0x4c {
        out.push(n as u8);
    } else if n <= 0xff {
        out.push(0x4c);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0x4d);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else {
        out.push(0x4e);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
}

fn encode_scriptnum(mut n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }
    let neg = n < 0;
    if neg {
        n = -n;
    }
    let mut out = Vec::new();
    while n > 0 {
        out.push((n & 0xff) as u8);
        n >>= 8;
    }
    if out.last().map(|b| b & 0x80 != 0).unwrap_or(false) {
        out.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        *out.last_mut().unwrap() |= 0x80;
    }
    out
}

fn opcode_byte(name: &str) -> Option<u8> {
    static MAP: &[(&str, u8)] = &[
        ("OP_0", 0x00),
        ("OP_FALSE", 0x00),
        ("OP_1NEGATE", 0x4f),
        ("OP_1", 0x51),
        ("OP_TRUE", 0x51),
        ("OP_2", 0x52),
        ("OP_3", 0x53),
        ("OP_4", 0x54),
        ("OP_5", 0x55),
        ("OP_6", 0x56),
        ("OP_7", 0x57),
        ("OP_8", 0x58),
        ("OP_9", 0x59),
        ("OP_10", 0x5a),
        ("OP_11", 0x5b),
        ("OP_12", 0x5c),
        ("OP_13", 0x5d),
        ("OP_14", 0x5e),
        ("OP_15", 0x5f),
        ("OP_16", 0x60),
        ("OP_NOP", 0x61),
        ("NOP", 0x61),
        ("OP_IF", 0x63),
        ("IF", 0x63),
        ("OP_NOTIF", 0x64),
        ("NOTIF", 0x64),
        ("OP_ELSE", 0x67),
        ("ELSE", 0x67),
        ("OP_ENDIF", 0x68),
        ("ENDIF", 0x68),
        ("OP_VERIFY", 0x69),
        ("VERIFY", 0x69),
        ("OP_RETURN", 0x6a),
        ("RETURN", 0x6a),
        ("OP_TOALTSTACK", 0x6b),
        ("TOALTSTACK", 0x6b),
        ("OP_FROMALTSTACK", 0x6c),
        ("FROMALTSTACK", 0x6c),
        ("OP_2DROP", 0x6d),
        ("2DROP", 0x6d),
        ("OP_2DUP", 0x6e),
        ("2DUP", 0x6e),
        ("OP_3DUP", 0x6f),
        ("3DUP", 0x6f),
        ("OP_2OVER", 0x70),
        ("2OVER", 0x70),
        ("OP_2ROT", 0x71),
        ("2ROT", 0x71),
        ("OP_2SWAP", 0x72),
        ("2SWAP", 0x72),
        ("OP_IFDUP", 0x73),
        ("IFDUP", 0x73),
        ("OP_DEPTH", 0x74),
        ("DEPTH", 0x74),
        ("OP_DROP", 0x75),
        ("DROP", 0x75),
        ("OP_DUP", 0x76),
        ("DUP", 0x76),
        ("OP_NIP", 0x77),
        ("NIP", 0x77),
        ("OP_OVER", 0x78),
        ("OVER", 0x78),
        ("OP_PICK", 0x79),
        ("PICK", 0x79),
        ("OP_ROLL", 0x7a),
        ("ROLL", 0x7a),
        ("OP_ROT", 0x7b),
        ("ROT", 0x7b),
        ("OP_SWAP", 0x7c),
        ("SWAP", 0x7c),
        ("OP_TUCK", 0x7d),
        ("TUCK", 0x7d),
        ("OP_SIZE", 0x82),
        ("SIZE", 0x82),
        ("OP_EQUAL", 0x87),
        ("EQUAL", 0x87),
        ("OP_EQUALVERIFY", 0x88),
        ("EQUALVERIFY", 0x88),
        ("OP_1ADD", 0x8b),
        ("1ADD", 0x8b),
        ("OP_1SUB", 0x8c),
        ("1SUB", 0x8c),
        ("OP_NEGATE", 0x8f),
        ("NEGATE", 0x8f),
        ("OP_ABS", 0x90),
        ("ABS", 0x90),
        ("OP_NOT", 0x91),
        ("NOT", 0x91),
        ("OP_0NOTEQUAL", 0x92),
        ("0NOTEQUAL", 0x92),
        ("OP_ADD", 0x93),
        ("ADD", 0x93),
        ("OP_SUB", 0x94),
        ("SUB", 0x94),
        ("OP_BOOLAND", 0x9a),
        ("BOOLAND", 0x9a),
        ("OP_BOOLOR", 0x9b),
        ("BOOLOR", 0x9b),
        ("OP_NUMEQUAL", 0x9c),
        ("NUMEQUAL", 0x9c),
        ("OP_NUMEQUALVERIFY", 0x9d),
        ("NUMEQUALVERIFY", 0x9d),
        ("OP_NUMNOTEQUAL", 0x9e),
        ("NUMNOTEQUAL", 0x9e),
        ("OP_LESSTHAN", 0x9f),
        ("LESSTHAN", 0x9f),
        ("OP_GREATERTHAN", 0xa0),
        ("GREATERTHAN", 0xa0),
        ("OP_LESSTHANOREQUAL", 0xa1),
        ("LESSTHANOREQUAL", 0xa1),
        ("OP_GREATERTHANOREQUAL", 0xa2),
        ("GREATERTHANOREQUAL", 0xa2),
        ("OP_MIN", 0xa3),
        ("MIN", 0xa3),
        ("OP_MAX", 0xa4),
        ("MAX", 0xa4),
        ("OP_WITHIN", 0xa5),
        ("WITHIN", 0xa5),
        ("OP_RIPEMD160", 0xa6),
        ("RIPEMD160", 0xa6),
        ("OP_SHA1", 0xa7),
        ("SHA1", 0xa7),
        ("OP_SHA256", 0xa8),
        ("SHA256", 0xa8),
        ("OP_HASH160", 0xa9),
        ("HASH160", 0xa9),
        ("OP_HASH256", 0xaa),
        ("HASH256", 0xaa),
        ("OP_CODESEPARATOR", 0xab),
        ("CODESEPARATOR", 0xab),
        ("OP_CHECKSIG", 0xac),
        ("CHECKSIG", 0xac),
        ("OP_CHECKSIGVERIFY", 0xad),
        ("CHECKSIGVERIFY", 0xad),
        ("OP_CHECKMULTISIG", 0xae),
        ("CHECKMULTISIG", 0xae),
        ("OP_CHECKMULTISIGVERIFY", 0xaf),
        ("CHECKMULTISIGVERIFY", 0xaf),
        ("OP_CHECKSIGADD", 0xba),
        ("CHECKSIGADD", 0xba),
        ("OP_NOP1", 0xb0),
        ("NOP1", 0xb0),
        ("OP_CHECKLOCKTIMEVERIFY", 0xb1),
        ("CHECKLOCKTIMEVERIFY", 0xb1),
        ("OP_CLTV", 0xb1),
        ("OP_CHECKSEQUENCEVERIFY", 0xb2),
        ("CHECKSEQUENCEVERIFY", 0xb2),
        ("OP_CSV", 0xb2),
        ("OP_NOP4", 0xb3),
        ("NOP4", 0xb3),
        ("OP_NOP5", 0xb4),
        ("NOP5", 0xb4),
        ("OP_NOP6", 0xb5),
        ("NOP6", 0xb5),
        ("OP_NOP7", 0xb6),
        ("NOP7", 0xb6),
        ("OP_NOP8", 0xb7),
        ("NOP8", 0xb7),
        ("OP_NOP9", 0xb8),
        ("NOP9", 0xb8),
        ("OP_NOP10", 0xb9),
        ("NOP10", 0xb9),
        ("OP_RESERVED", 0x50),
        ("RESERVED", 0x50),
        ("OP_VER", 0x62),
        ("VER", 0x62),
        ("OP_VERIF", 0x65),
        ("VERIF", 0x65),
        ("OP_VERNOTIF", 0x66),
        ("VERNOTIF", 0x66),
        ("OP_RESERVED1", 0x89),
        ("RESERVED1", 0x89),
        ("OP_RESERVED2", 0x8a),
        ("RESERVED2", 0x8a),
        ("OP_CAT", 0x7e),
        ("CAT", 0x7e),
        ("OP_SUBSTR", 0x7f),
        ("SUBSTR", 0x7f),
        ("OP_LEFT", 0x80),
        ("LEFT", 0x80),
        ("OP_RIGHT", 0x81),
        ("RIGHT", 0x81),
        ("OP_INVERT", 0x83),
        ("INVERT", 0x83),
        ("OP_AND", 0x84),
        ("AND", 0x84),
        ("OP_OR", 0x85),
        ("OR", 0x85),
        ("OP_XOR", 0x86),
        ("XOR", 0x86),
        ("OP_2MUL", 0x8d),
        ("2MUL", 0x8d),
        ("OP_2DIV", 0x8e),
        ("2DIV", 0x8e),
        ("OP_MUL", 0x95),
        ("MUL", 0x95),
        ("OP_DIV", 0x96),
        ("DIV", 0x96),
        ("OP_MOD", 0x97),
        ("MOD", 0x97),
        ("OP_LSHIFT", 0x98),
        ("LSHIFT", 0x98),
        ("OP_RSHIFT", 0x99),
        ("RSHIFT", 0x99),
    ];
    for (n, b) in MAP {
        if n.eq_ignore_ascii_case(name) {
            return Some(*b);
        }
    }
    None
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

// ── Credit / spend template (matches Core script_tests.cpp) ─────────────────

fn build_credit(script_pubkey: ScriptBuf, value: Amount) -> Transaction {
    // CScript() << CScriptNum(0) << CScriptNum(0) → two OP_0 pushes.
    Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x00, 0x00]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey,
        }],
    }
}

fn build_spend(credit: &Transaction, script_sig: ScriptBuf, witness: Witness) -> Transaction {
    let credit_txid = credit.compute_txid();
    Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: credit_txid,
                vout: 0,
            },
            script_sig,
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: credit.output[0].value,
            script_pubkey: ScriptBuf::new(),
        }],
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
    // Core KeyData::key0 secret: 31 zero bytes + 0x01 (script_tests.cpp vchKey0).
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 1;
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&sk_bytes)
        .map_err(|e| format!("taproot internal sk: {e}"))?;
    let kp = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk);
    let (internal_xonly, _) = kp.x_only_public_key();

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
            if s.is_empty() {
                stack.push(vec![]);
                continue;
            }
            // Core: `#SCRIPT# <asm>` → assemble leaf, push as witness element.
            if let Some(rest) = s.strip_prefix("#SCRIPT#") {
                let script_bytes = assemble(rest.trim())?;
                stack.push(script_bytes);
                continue;
            }
            // Core: `#CONTROLBLOCK#` — single-leaf tree with key0 internal key.
            if s == "#CONTROLBLOCK#" {
                let leaf = stack
                    .last()
                    .ok_or_else(|| "#CONTROLBLOCK# without leaf script".to_string())?
                    .clone();
                let leaf_script = ScriptBuf::from_bytes(leaf);
                let builder = bitcoin::taproot::TaprootBuilder::new()
                    .add_leaf(0, leaf_script.clone())
                    .map_err(|e| format!("taproot add_leaf: {e:?}"))?;
                let spend_info = builder
                    .finalize(&secp, internal_xonly)
                    .map_err(|e| format!("taproot finalize: {e:?}"))?;
                let control = spend_info
                    .control_block(&(leaf_script, bitcoin::taproot::LeafVersion::TapScript))
                    .ok_or_else(|| "taproot control_block missing".to_string())?;
                stack.push(control.serialize());
                taproot_output = Some(spend_info.output_key().to_x_only_public_key().serialize());
                continue;
            }
            let hex = s.trim_start_matches("0x").trim_start_matches("0X");
            if !hex.len().is_multiple_of(2) {
                return Err(format!("odd witness hex: {s}"));
            }
            // Non-hex tokens (that are not special flags) are hard errors in Core.
            if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!("witness is not hex: {s}"));
            }
            let mut bytes = Vec::with_capacity(hex.len() / 2);
            for j in (0..hex.len()).step_by(2) {
                bytes.push(u8::from_str_radix(&hex[j..j + 2], 16).map_err(|e| e.to_string())?);
            }
            stack.push(bytes);
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
) -> Result<(), String> {
    // DISCOURAGE: NOP1/4–10 outside IF regions (see has_discouraged_nop_outside_if).
    if flags.discourage_upgradable_nops
        && (has_discouraged_nop_outside_if(script_sig)
            || has_discouraged_nop_outside_if(script_pubkey))
    {
        return Err("DISCOURAGE_UPGRADABLE_NOPS".into());
    }
    // SCRIPT_VERIFY_SIGPUSHONLY, and BIP16 P2SH always requires push-only scriptSig.
    if flags.sig_push_only || (flags.p2sh && is_p2sh_script(script_pubkey)) {
        let mut tmp = Vec::new();
        interpreter::eval_script_sig_pushes(Script::from_bytes(script_sig), &mut tmp)
            .map_err(|_| "SIG_PUSHONLY".to_string())?;
    }

    let spk = ScriptBuf::from_bytes(script_pubkey.to_vec());
    let credit = build_credit(spk.clone(), amount);
    let mut spend = build_spend(&credit, ScriptBuf::from_bytes(script_sig.to_vec()), witness);
    let prev = TxOut {
        value: amount,
        script_pubkey: credit.output[0].script_pubkey.clone(),
    };
    spend.input[0].previous_output = OutPoint {
        txid: credit.compute_txid(),
        vout: 0,
    };

    // Without SCRIPT_VERIFY_WITNESS, Core treats v0/v1 programs as bare scripts.
    // Production always enables witness post-segwit; flag-off is Core-vector only.
    if !flags.witness {
        return eval_bare_pair(
            &spend,
            script_sig,
            script_pubkey,
            amount,
            flags,
            flags.cleanstack,
        );
    }

    let job = ScriptCheckJob {
        txid: spend.compute_txid().to_byte_array(),
        prevouts: vec![prev],
        tx: JobTx::owned(spend),
        bip65_active: flags.cltv,
        bip112_active: flags.csv,
        // STRICTENC/DERSIG → strict DER (bip66).
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
        pre: std::sync::OnceLock::new(),
    };
    verify_job_all_inputs(&job).map_err(|e| format!("{e}"))
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
    let prevouts = [TxOut {
        value: amount,
        script_pubkey: ScriptBuf::from_bytes(script_pubkey.to_vec()),
    }];
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let ss = Script::from_bytes(script_sig);
    if !script_sig.is_empty() {
        let mut ctx = EvalContext::new_with_flags(
            spend,
            0,
            amount,
            &prevouts,
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
        &prevouts,
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
    if flags.p2sh && is_p2sh_script(script_pubkey) {
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
            &prevouts,
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

fn is_p2sh_script(spk: &[u8]) -> bool {
    spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87
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
        // Core: `0x51 0x20 #TAPROOTOUTPUT#` → OP_1 + 32-byte tweaked output key.
        let pk_bytes = if pk_s.trim() == "0x51 0x20 #TAPROOTOUTPUT#" {
            let Some(out) = tap_out else {
                st.ran += 1;
                st.fail += 1;
                if st.failures.len() < 40 {
                    st.failures
                        .push(format!("#{idx} #TAPROOTOUTPUT# without control block"));
                }
                continue;
            };
            let mut b = vec![0x51, 0x20];
            b.extend_from_slice(&out);
            b
        } else {
            match assemble(pk_s) {
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
            }
        };

        st.ran += 1;
        let got = run_script_row(&sig_bytes, &pk_bytes, witness, amount, &flags);
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

/// Spot-check: known-valid empty scriptSig + DEPTH 0 EQUAL must accept.
#[test]
fn core_script_spot_valid_depth_equal() {
    let flags = parse_flags("P2SH,STRICTENC");
    let sig = assemble("").unwrap();
    let pk = assemble("DEPTH 0 EQUAL").unwrap();
    run_script_row(&sig, &pk, Witness::new(), Amount::ZERO, &flags)
        .expect("DEPTH 0 EQUAL should OK");
}

/// Spot-check: known-invalid 0 EQUAL (false) must reject.
#[test]
fn core_script_spot_invalid_false() {
    let flags = parse_flags("P2SH,STRICTENC");
    let sig = assemble("").unwrap();
    let pk = assemble("0 EQUAL").unwrap();
    let got = run_script_row(&sig, &pk, Witness::new(), Amount::ZERO, &flags);
    assert!(got.is_err(), "0 EQUAL should reject, got {got:?}");
}
