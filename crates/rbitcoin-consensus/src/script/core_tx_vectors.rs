#![cfg(test)]

//! Bitcoin Core `tx_valid.json` / `tx_invalid.json` harness.
//!
//! Every data row is deserialized and verified through the **shipped**
//! [`rbitcoin_consensus::script::verify_job_all_inputs`] path with prevouts
//! from the fixture. Expected accept (valid) / reject (invalid) is required
//! for **all** data rows — no allowlist or skip inventory.

use crate::block::{JobTx, ScriptCheckJob};
use crate::script;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    super::core_fixture::stage_core_json(name)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let h = s.trim();
    if !h.len().is_multiple_of(2) {
        return Err(format!("odd hex len {}", h.len()));
    }
    let mut out = Vec::with_capacity(h.len() / 2);
    for i in (0..h.len()).step_by(2) {
        out.push(u8::from_str_radix(&h[i..i + 2], 16).map_err(|e| e.to_string())?);
    }
    Ok(out)
}

fn load_array(name: &str) -> Vec<Value> {
    let path = fixture(name);
    let s = fs::read_to_string(&path).unwrap_or_else(|e| panic!("missing {path:?}: {e}"));
    let v: Value = serde_json::from_str(&s).unwrap_or_else(|e| panic!("parse {name}: {e}"));
    v.as_array()
        .cloned()
        .unwrap_or_else(|| panic!("{name}: root not array"))
}

/// Assemble Core script language (shared semantics with unit core_vectors).
fn assemble_script(src: &str) -> Result<Vec<u8>, String> {
    // Minimal reimplementation matching core_vectors::assemble for prevout scripts.
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
        // Core ParseScript: -1, 0, 1..16 are single opcodes (MINIMALDATA-safe).
        if let Ok(n) = tok.parse::<i64>() {
            if n == 0 {
                out.push(0x00);
            } else if n == -1 {
                out.push(0x4f);
            } else if (1..=16).contains(&n) {
                out.push(0x50 + n as u8);
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
    // Same map as unit core_vectors (subset sufficient for fixtures).
    const MAP: &[(&str, u8)] = &[
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
        ("OP_DUP", 0x76),
        ("DUP", 0x76),
        ("OP_DROP", 0x75),
        ("DROP", 0x75),
        ("OP_EQUAL", 0x87),
        ("EQUAL", 0x87),
        ("OP_EQUALVERIFY", 0x88),
        ("EQUALVERIFY", 0x88),
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
        ("OP_CHECKLOCKTIMEVERIFY", 0xb1),
        ("CHECKLOCKTIMEVERIFY", 0xb1),
        ("OP_CLTV", 0xb1),
        ("OP_CHECKSEQUENCEVERIFY", 0xb2),
        ("CHECKSEQUENCEVERIFY", 0xb2),
        ("OP_CSV", 0xb2),
        ("OP_NOP1", 0xb0),
        ("NOP1", 0xb0),
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
        ("OP_NOT", 0x91),
        ("NOT", 0x91),
        ("OP_1ADD", 0x8b),
        ("1ADD", 0x8b),
        ("OP_1SUB", 0x8c),
        ("1SUB", 0x8c),
        ("OP_NEGATE", 0x8f),
        ("NEGATE", 0x8f),
        ("OP_ABS", 0x90),
        ("ABS", 0x90),
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
        ("OP_SIZE", 0x82),
        ("SIZE", 0x82),
        ("OP_RIPEMD160", 0xa6),
        ("RIPEMD160", 0xa6),
        ("OP_SHA1", 0xa7),
        ("SHA1", 0xa7),
        ("OP_SHA256", 0xa8),
        ("SHA256", 0xa8),
        ("OP_TOALTSTACK", 0x6b),
        ("TOALTSTACK", 0x6b),
        ("OP_FROMALTSTACK", 0x6c),
        ("FROMALTSTACK", 0x6c),
        ("OP_IFDUP", 0x73),
        ("IFDUP", 0x73),
        ("OP_DEPTH", 0x74),
        ("DEPTH", 0x74),
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
    ];
    for (n, b) in MAP {
        if n.eq_ignore_ascii_case(name) {
            return Some(*b);
        }
    }
    None
}

/// Script flags we implement for Core tx corpora.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct TxFlags {
    p2sh: bool,
    dersig: bool,
    cltv: bool,
    csv: bool,
    witness: bool,
    taproot: bool,
    low_s: bool,
    strictenc: bool,
    nullfail: bool,
    null_dummy: bool,
    minimal_data: bool,
    discourage_upgradable_witness: bool,
    witness_pubkeytype: bool,
    /// SCRIPT_VERIFY_CONST_SCRIPTCODE: reject CODESEPARATOR / FindAndDelete hits.
    const_scriptcode: bool,
    /// SCRIPT_VERIFY_CLEANSTACK (witness cleanstack after eval).
    cleanstack: bool,
    /// SCRIPT_VERIFY_SIGPUSHONLY.
    sig_push_only: bool,
    /// SCRIPT_VERIFY_MINIMALIF.
    minimal_if: bool,
    /// Core fixture token: CheckTransaction fails (no script verify).
    badtx: bool,
}

/// All named flags we can enable for inverted `tx_valid` semantics.
fn all_implemented_flags() -> TxFlags {
    TxFlags {
        p2sh: true,
        dersig: true,
        cltv: true,
        csv: true,
        witness: true,
        taproot: true,
        low_s: true,
        strictenc: true,
        nullfail: true,
        null_dummy: true,
        minimal_data: true,
        discourage_upgradable_witness: true,
        witness_pubkeytype: true,
        const_scriptcode: true,
        cleanstack: true,
        sig_push_only: true,
        minimal_if: true,
        badtx: false,
    }
}

fn parse_named_flag_bits(s: &str) -> TxFlags {
    let mut f = TxFlags::default();
    if s.is_empty() || s.eq_ignore_ascii_case("NONE") {
        return f;
    }
    for part in s.split(',') {
        match part.trim().to_uppercase().as_str() {
            "P2SH" => f.p2sh = true,
            "DERSIG" => f.dersig = true,
            "STRICTENC" => {
                f.dersig = true;
                f.strictenc = true;
            }
            "LOW_S" => {
                f.low_s = true;
                f.dersig = true;
            }
            "NULLFAIL" => f.nullfail = true,
            "NULLDUMMY" => f.null_dummy = true,
            "MINIMALDATA" => f.minimal_data = true,
            "CHECKLOCKTIMEVERIFY" => f.cltv = true,
            "CHECKSEQUENCEVERIFY" => f.csv = true,
            "WITNESS" => f.witness = true,
            "TAPROOT" | "TAPSCRIPT" => {
                f.taproot = true;
                f.witness = true;
            }
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => f.discourage_upgradable_witness = true,
            "WITNESS_PUBKEYTYPE" => f.witness_pubkeytype = true,
            "CONST_SCRIPTCODE" => f.const_scriptcode = true,
            "CLEANSTACK" => {
                f.cleanstack = true;
                // Core FillFlags: CLEANSTACK implies WITNESS (and WITNESS implies P2SH).
                f.witness = true;
                f.p2sh = true;
            }
            "SIGPUSHONLY" => f.sig_push_only = true,
            "MINIMALIF" => f.minimal_if = true,
            "BADTX" => f.badtx = true,
            _ => {}
        }
    }
    // Core FillFlags: WITNESS implies P2SH.
    if f.witness {
        f.p2sh = true;
    }
    f
}

/// Core `tx_valid.json`: flags string lists flags that stay **unset**; all others on.
/// `NONE` → all implemented flags enabled.
fn parse_tx_valid_flags(s: &str) -> TxFlags {
    let disabled = parse_named_flag_bits(s);
    let mut f = all_implemented_flags();
    // Disable bits listed in the fixture string.
    if disabled.p2sh {
        f.p2sh = false;
    }
    if disabled.dersig {
        f.dersig = false;
    }
    if disabled.cltv {
        f.cltv = false;
    }
    if disabled.csv {
        f.csv = false;
    }
    if disabled.witness {
        f.witness = false;
    }
    if disabled.taproot {
        f.taproot = false;
    }
    if disabled.low_s {
        f.low_s = false;
    }
    if disabled.strictenc {
        f.strictenc = false;
    }
    if disabled.nullfail {
        f.nullfail = false;
    }
    if disabled.null_dummy {
        f.null_dummy = false;
    }
    if disabled.minimal_data {
        f.minimal_data = false;
    }
    if disabled.discourage_upgradable_witness {
        f.discourage_upgradable_witness = false;
    }
    if disabled.witness_pubkeytype {
        f.witness_pubkeytype = false;
    }
    if disabled.const_scriptcode {
        f.const_scriptcode = false;
    }
    if disabled.cleanstack {
        f.cleanstack = false;
    }
    if disabled.sig_push_only {
        f.sig_push_only = false;
    }
    if disabled.minimal_if {
        f.minimal_if = false;
    }
    // Re-apply FillFlags implications after disables.
    if f.cleanstack {
        f.witness = true;
        f.p2sh = true;
    }
    if f.witness {
        f.p2sh = true;
    }
    f
}

/// Core `tx_invalid.json`: flags string lists flags that are **set** (except BADTX).
fn parse_tx_invalid_flags(s: &str) -> TxFlags {
    parse_named_flag_bits(s)
}

fn fill_implied(f: &mut TxFlags) {
    if f.taproot {
        f.witness = true;
    }
    if f.cleanstack {
        f.witness = true;
        f.p2sh = true;
    }
    if f.witness {
        f.p2sh = true;
    }
    if f.strictenc || f.low_s {
        f.dersig = true;
    }
}

fn flags_to_job(tx: Transaction, prevouts: Vec<TxOut>, flags: &TxFlags) -> ScriptCheckJob {
    ScriptCheckJob {
        txid: tx.compute_txid().to_byte_array(),
        prevouts,
        tx: JobTx::owned(tx),
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
        witness_pubkeytype: flags.witness_pubkeytype,
        witness_active: flags.witness,
        discourage_upgradable_witness: flags.discourage_upgradable_witness,
        const_scriptcode: flags.const_scriptcode,
        pre: std::sync::OnceLock::new(),
    }
}

fn flag_on(f: &TxFlags, i: usize) -> bool {
    match i {
        0 => f.p2sh,
        1 => f.dersig,
        2 => f.cltv,
        3 => f.csv,
        4 => f.witness,
        5 => f.taproot,
        6 => f.low_s,
        7 => f.strictenc,
        8 => f.nullfail,
        9 => f.null_dummy,
        10 => f.minimal_data,
        11 => f.discourage_upgradable_witness,
        12 => f.witness_pubkeytype,
        13 => f.const_scriptcode,
        14 => f.sig_push_only,
        15 => f.minimal_if,
        _ => false,
    }
}

const TOGGLE_N: usize = 16;
const I_P2SH: usize = 0;
const I_WITNESS: usize = 4;
const I_TAPROOT: usize = 5;

fn with_flag(mut f: TxFlags, i: usize, on: bool) -> TxFlags {
    match i {
        0 => f.p2sh = on,
        1 => f.dersig = on,
        2 => f.cltv = on,
        3 => f.csv = on,
        4 => f.witness = on,
        5 => f.taproot = on,
        6 => f.low_s = on,
        7 => f.strictenc = on,
        8 => f.nullfail = on,
        9 => f.null_dummy = on,
        10 => f.minimal_data = on,
        11 => f.discourage_upgradable_witness = on,
        12 => f.witness_pubkeytype = on,
        13 => f.const_scriptcode = on,
        14 => f.sig_push_only = on,
        15 => f.minimal_if = on,
        _ => {}
    }
    fill_implied(&mut f);
    f
}

/// Parse one prevout entry: [txid_hex, vout, scriptPubKey_scriptlang, amount?]
fn parse_prevout(cell: &Value) -> Result<(bitcoin::Txid, u32, TxOut), String> {
    let a = cell
        .as_array()
        .ok_or_else(|| "prevout not array".to_string())?;
    if a.len() < 3 {
        return Err(format!("prevout short: {a:?}"));
    }
    let txid_hex = a[0].as_str().ok_or("txid")?;
    // Core JSON uses display-order hex (`GetHex`); rust-bitcoin `from_str` matches.
    let txid: bitcoin::Txid = txid_hex
        .parse()
        .map_err(|e| format!("txid parse {txid_hex}: {e}"))?;
    let vout = a[1]
        .as_u64()
        .or_else(|| a[1].as_i64().map(|x| x as u64))
        .unwrap_or(0) as u32;
    let spk_s = a[2].as_str().ok_or("scriptPubKey")?;
    let spk = ScriptBuf::from_bytes(assemble_script(spk_s)?);
    // Core tx_valid/tx_invalid amounts are integer **satoshis** (not BTC floats).
    let value = if a.len() >= 4 {
        if let Some(n) = a[3].as_u64() {
            Amount::from_sat(n)
        } else if let Some(n) = a[3].as_i64() {
            Amount::from_sat(n.max(0) as u64)
        } else if let Some(n) = a[3].as_f64() {
            // Integer-valued JSON numbers may appear as f64.
            Amount::from_sat(n.max(0.0).round() as u64)
        } else {
            Amount::ZERO
        }
    } else {
        Amount::ZERO
    };
    Ok((
        txid,
        vout,
        TxOut {
            value,
            script_pubkey: spk,
        },
    ))
}

/// Core `CheckTransaction` (context-free structural consensus checks).
fn check_transaction_struct(tx: &Transaction) -> Result<(), String> {
    const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
    if tx.input.is_empty() {
        return Err("BADTX: vin empty".into());
    }
    if tx.output.is_empty() {
        return Err("BADTX: vout empty".into());
    }
    // Output value range + sum (CVE-2010-5139).
    let mut n_value_out: u64 = 0;
    for o in &tx.output {
        let v = o.value.to_sat();
        // rust-bitcoin Amount is non-negative; oversized still possible.
        if v > MAX_MONEY {
            return Err("BADTX: vout toolarge".into());
        }
        n_value_out = n_value_out
            .checked_add(v)
            .ok_or_else(|| "BADTX: vouttotal toolarge".to_string())?;
        if n_value_out > MAX_MONEY {
            return Err("BADTX: vouttotal toolarge".into());
        }
    }
    // Duplicate inputs (CVE-2018-17144).
    let mut seen = std::collections::HashSet::new();
    for vin in &tx.input {
        let key = (vin.previous_output.txid, vin.previous_output.vout);
        if !seen.insert(key) {
            return Err("BADTX: inputs duplicate".into());
        }
    }
    if tx.is_coinbase() {
        let ss = tx.input[0].script_sig.as_bytes().len();
        if !(2..=100).contains(&ss) {
            return Err("BADTX: bad-cb-length".into());
        }
    } else {
        for vin in &tx.input {
            if vin.previous_output.is_null() {
                return Err("BADTX: prevout null".into());
            }
        }
    }
    Ok(())
}

fn verify_tx_row(
    prevouts_json: &Value,
    tx_hex: &str,
    flags_s: &str,
    expect_ok: bool,
) -> Result<(), String> {
    let prev_arr = prevouts_json
        .as_array()
        .ok_or_else(|| "prevouts not array".to_string())?;
    let mut map: std::collections::HashMap<(bitcoin::Txid, u32), TxOut> =
        std::collections::HashMap::new();
    for p in prev_arr {
        let (txid, vout, txo) = parse_prevout(p)?;
        map.insert((txid, vout), txo);
    }
    let tx_bytes = decode_hex(tx_hex)?;
    let tx: Transaction = deserialize(&tx_bytes).map_err(|e| format!("tx deser: {e}"))?;

    // Core: BADTX / CheckTransaction failures reject the tx (no script verify).
    // Harness for expect_ok=false requires Err; for expect_ok=true requires Ok.
    if let Err(e) = check_transaction_struct(&tx) {
        return Err(e);
    }

    let mut prevouts = Vec::with_capacity(tx.input.len());
    for vin in &tx.input {
        let key = (vin.previous_output.txid, vin.previous_output.vout);
        let po = map
            .get(&key)
            .cloned()
            .ok_or_else(|| format!("missing prevout {key:?}"))?;
        prevouts.push(po);
    }
    // Core: tx_valid uses ~flags; tx_invalid uses flags as enable set.
    let flags = if expect_ok {
        parse_tx_valid_flags(flags_s)
    } else {
        parse_tx_invalid_flags(flags_s)
    };
    verify_parsed_tx(&tx, prevouts, &flags)
}

fn verify_parsed_tx(tx: &Transaction, prevouts: Vec<TxOut>, flags: &TxFlags) -> Result<(), String> {
    if flags.sig_push_only {
        for vin in &tx.input {
            let mut tmp = Vec::new();
            script::interpreter::eval_script_sig_pushes(vin.script_sig.as_script(), &mut tmp)
                .map_err(|_| "SIG_PUSHONLY".to_string())?;
        }
    }
    let job = flags_to_job(tx.clone(), prevouts, flags);
    script::verify_job_all_inputs(&job).map_err(|e| format!("{e}"))
}

fn run_tx_corpus(name: &str, expect_ok: bool) -> (u32, u32, u32, Vec<String>) {
    let rows = load_array(name);
    let mut total = 0u32;
    let mut pass = 0u32;
    let mut fail = 0u32;
    let mut failures = Vec::new();

    for (idx, row) in rows.iter().enumerate() {
        let Value::Array(cells) = row else {
            continue;
        };
        if cells.is_empty() || !cells[0].is_array() {
            continue;
        }
        if cells.len() < 3 {
            continue;
        }
        let Some(tx_hex) = cells[1].as_str() else {
            continue;
        };
        let flags_s = cells[2].as_str().unwrap_or("NONE");
        total += 1;
        let got = verify_tx_row(&cells[0], tx_hex, flags_s, expect_ok);
        let ok = if expect_ok { got.is_ok() } else { got.is_err() };
        if ok {
            pass += 1;
        } else {
            fail += 1;
            if failures.len() < 30 {
                failures.push(format!(
                    "#{idx} flags={flags_s} expect_ok={expect_ok} got={got:?} tx={}…",
                    &tx_hex[..tx_hex.len().min(32)]
                ));
            }
        }
    }
    (total, pass, fail, failures)
}

#[test]
fn core_tx_valid_all_rows() {
    let (total, pass, fail, failures) = run_tx_corpus("tx_valid.json", true);
    eprintln!("core tx_valid: total={total} pass={pass} fail={fail}");
    for f in &failures {
        eprintln!("  FAIL {f}");
    }
    assert!(total > 50, "expected many valid rows, total={total}");
    assert_eq!(fail, 0, "tx_valid failures: {fail}");
    assert_eq!(pass, total, "every valid row must pass");
}

#[test]
fn core_tx_invalid_all_rows() {
    let (total, pass, fail, failures) = run_tx_corpus("tx_invalid.json", false);
    eprintln!("core tx_invalid: total={total} pass={pass} fail={fail}");
    for f in &failures {
        eprintln!("  FAIL {f}");
    }
    assert!(total > 50, "expected many invalid rows, total={total}");
    assert_eq!(fail, 0, "tx_invalid failures: {fail}");
    assert_eq!(pass, total, "every invalid row must reject as expected");
}

/// Spot-check: fixtures load and at least one valid row accepts via shipped path.
#[test]
fn core_tx_spot_first_valid_accepts() {
    let rows = load_array("tx_valid.json");
    let mut tried = 0u32;
    for row in &rows {
        let Value::Array(cells) = row else { continue };
        if cells.len() < 3 || !cells[0].is_array() {
            continue;
        }
        let Some(tx_hex) = cells[1].as_str() else {
            continue;
        };
        let flags = cells[2].as_str().unwrap_or("NONE");
        tried += 1;
        if verify_tx_row(&cells[0], tx_hex, flags, true).is_ok() {
            return;
        }
        if tried >= 40 {
            break;
        }
    }
    // At least one of the first 40 data rows must accept on the shipped path.
    panic!("no accepting tx_valid row in first {tried} data rows");
}

fn load_tx_data_rows(name: &str) -> Vec<(Value, String, String)> {
    let mut out = Vec::new();
    for row in load_array(name) {
        let Value::Array(cells) = row else {
            continue;
        };
        if cells.len() < 3 || !cells[0].is_array() {
            continue;
        }
        let Some(tx_hex) = cells[1].as_str() else {
            continue;
        };
        let flags_s = cells[2].as_str().unwrap_or("NONE").to_string();
        out.push((cells[0].clone(), tx_hex.to_string(), flags_s));
    }
    out
}

/// Core `transaction_tests.cpp`: a valid row still accepts with any extra
/// implemented flag turned off, unless FillFlags would turn it back on.
#[test]
fn core_tx_valid_flag_subsets() {
    let mut n = 0u32;
    for (prev, tx_hex, flags_s) in load_tx_data_rows("tx_valid.json") {
        let flags = parse_tx_valid_flags(&flags_s);
        let tx_bytes = decode_hex(&tx_hex).expect("hex");
        let tx: Transaction = deserialize(&tx_bytes).expect("tx");
        let mut map = std::collections::HashMap::new();
        for p in prev.as_array().expect("prevouts") {
            let (txid, vout, txo) = parse_prevout(p).expect("prevout");
            map.insert((txid, vout), txo);
        }
        let mut prevouts = Vec::new();
        for vin in &tx.input {
            prevouts.push(
                map.get(&(vin.previous_output.txid, vin.previous_output.vout))
                    .cloned()
                    .expect("missing prevout"),
            );
        }
        for i in 0..TOGGLE_N {
            if !flag_on(&flags, i) {
                continue;
            }
            let less = with_flag(flags.clone(), i, false);
            if flag_on(&less, i) {
                continue;
            }
            n += 1;
            verify_parsed_tx(&tx, prevouts.clone(), &less).unwrap_or_else(|e| {
                panic!("tx_valid subset i={i} flags={flags_s} still-on-row must accept: {e}")
            });
        }
    }
    assert!(n > 0, "expected some subset toggles");
}

/// Core `transaction_tests.cpp`: an invalid row still rejects with any extra
/// implemented flag turned on. BADTX rows are structural (no script flags).
#[test]
fn core_tx_invalid_flag_supersets() {
    let mut n = 0u32;
    for (prev, tx_hex, flags_s) in load_tx_data_rows("tx_invalid.json") {
        let flags = parse_tx_invalid_flags(&flags_s);
        if flags.badtx {
            continue;
        }
        let tx_bytes = decode_hex(&tx_hex).expect("hex");
        let tx: Transaction = deserialize(&tx_bytes).expect("tx");
        if check_transaction_struct(&tx).is_err() {
            continue;
        }
        let mut map = std::collections::HashMap::new();
        for p in prev.as_array().expect("prevouts") {
            let (txid, vout, txo) = parse_prevout(p).expect("prevout");
            map.insert((txid, vout), txo);
        }
        let mut prevouts = Vec::new();
        let mut missing = false;
        for vin in &tx.input {
            match map.get(&(vin.previous_output.txid, vin.previous_output.vout)) {
                Some(po) => prevouts.push(po.clone()),
                None => {
                    missing = true;
                    break;
                }
            }
        }
        if missing {
            continue;
        }
        for i in 0..TOGGLE_N {
            if i == I_P2SH || i == I_WITNESS || i == I_TAPROOT {
                continue;
            }
            if flag_on(&flags, i) {
                continue;
            }
            let more = with_flag(flags.clone(), i, true);
            if more == flags {
                continue;
            }
            n += 1;
            verify_parsed_tx(&tx, prevouts.clone(), &more).expect_err(&format!(
                "tx_invalid superset i={i} flags={flags_s} must still reject"
            ));
        }
    }
    assert!(n > 0, "expected some superset toggles");
}
