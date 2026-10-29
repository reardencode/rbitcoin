//! Shared Core script-language assembler and hex decode (unit-test only).

pub fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    rbitcoin_primitives::hex_decode(s.trim()).map_err(|e| e.to_string())
}

/// Assemble Core script string ("1 2 ADD", "0x4c 0x01 0x07", "'Az'") to bytes.
pub fn assemble_script(src: &str) -> Result<Vec<u8>, String> {
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
            crate::script::interpreter::encode_push(&mut out, s.as_bytes());
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
                let enc = rbitcoin_primitives::scriptnum_encode(n);
                crate::script::interpreter::encode_push(&mut out, &enc);
            }
            continue;
        }
        let op = opcode_byte(tok).ok_or_else(|| format!("unknown token {tok}"))?;
        out.push(op);
    }
    Ok(out)
}

#[doc(hidden)]
pub fn opcode_byte(name: &str) -> Option<u8> {
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

/// `scriptPubKey` cell, including Core's `#TAPROOTOUTPUT#` placeholder.
pub fn assemble_script_pubkey(src: &str, tap_out: Option<[u8; 32]>) -> Result<Vec<u8>, String> {
    if src.trim() == "0x51 0x20 #TAPROOTOUTPUT#" {
        let out = tap_out.ok_or_else(|| "#TAPROOTOUTPUT# without control block".to_string())?;
        let mut b = rbitcoin_primitives::P2TR_PREFIX.to_vec();
        b.extend_from_slice(&out);
        return Ok(b);
    }
    assemble_script(src)
}

/// Control block and tweaked output key for one tapscript leaf.
///
/// Internal key is Core `script_tests.cpp` `vchKey0`: 31 zero bytes, then `0x01`.
pub fn taproot_leaf_control(leaf: &[u8]) -> Result<(Vec<u8>, [u8; 32]), String> {
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use bitcoin::taproot::{LeafVersion, TaprootBuilder};

    let secp = Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 1;
    let sk = SecretKey::from_slice(&sk_bytes).map_err(|e| format!("taproot internal sk: {e}"))?;
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (internal_xonly, _) = kp.x_only_public_key();
    let leaf_script = bitcoin::script::ScriptBuf::from_bytes(leaf.to_vec());
    let builder = TaprootBuilder::new()
        .add_leaf(0, leaf_script.clone())
        .map_err(|e| format!("taproot add_leaf: {e:?}"))?;
    let spend_info = builder
        .finalize(&secp, internal_xonly)
        .map_err(|e| format!("taproot finalize: {e:?}"))?;
    let control = spend_info
        .control_block(&(leaf_script, LeafVersion::TapScript))
        .ok_or_else(|| "taproot control_block missing".to_string())?;
    let output = spend_info.output_key().to_x_only_public_key().serialize();
    Ok((control.serialize(), output))
}

/// Spend-transaction fields both corpus runners share.
///
/// Defaults match Core `script_tests.cpp`: version 1, locktime 0, sequence
/// `0xffffffff`, one empty output. `version` is the consensus `i32` bit
/// pattern (`4294967295` and `-1` are the same bits).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendShape {
    pub version: i32,
    pub lock_time: u32,
    pub sequence: u32,
    pub n_outputs: usize,
}

impl Default for SpendShape {
    fn default() -> Self {
        Self {
            version: 1,
            lock_time: 0,
            sequence: u32::MAX,
            n_outputs: 1,
        }
    }
}

/// Optional `"spend"` object on a corpus row. Missing object keeps [`SpendShape::default`].
pub fn spend_shape_from_json(v: Option<&serde_json::Value>) -> Result<SpendShape, String> {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(SpendShape::default());
    };
    let obj = v.as_object().ok_or("spend must be an object")?;
    let mut shape = SpendShape::default();
    if let Some(n) = obj.get("version") {
        let bits = n.as_i64().ok_or("spend.version")?;
        shape.version = bits as i32;
    }
    if let Some(n) = obj.get("locktime") {
        shape.lock_time = u32_field(n, "spend.locktime")?;
    }
    if let Some(n) = obj.get("sequence") {
        shape.sequence = u32_field(n, "spend.sequence")?;
    }
    if let Some(n) = obj.get("n_outputs") {
        let u = n.as_u64().ok_or("spend.n_outputs")?;
        shape.n_outputs = usize::try_from(u).map_err(|_| "spend.n_outputs")?;
    }
    Ok(shape)
}

#[doc(hidden)]
pub fn u32_field(n: &serde_json::Value, name: &str) -> Result<u32, String> {
    let u = n.as_u64().ok_or(name)?;
    u32::try_from(u).map_err(|_| name.to_string())
}

/// Core `script_tests.cpp` credit transaction plus the spend under test.
///
/// Credit stays version 1, locktime 0, two `OP_0` pushes, sequence max, one
/// output. `shape` applies to the spend only (script locktime and sequence
/// read that transaction).
pub fn credit_and_spend(
    script_pubkey: bitcoin::ScriptBuf,
    script_sig: bitcoin::ScriptBuf,
    witness: bitcoin::Witness,
    amount: bitcoin::Amount,
    shape: SpendShape,
) -> (bitcoin::Transaction, bitcoin::Transaction) {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut};

    let credit = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::from_bytes(vec![0x00, 0x00]),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: amount,
            script_pubkey: script_pubkey.clone(),
        }],
    };
    let spend = Transaction {
        version: Version(shape.version),
        lock_time: LockTime::from_consensus(shape.lock_time),
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: credit.compute_txid(),
                vout: 0,
            },
            script_sig,
            sequence: Sequence::from_consensus(shape.sequence),
            witness,
        }],
        output: std::iter::repeat_with(|| TxOut {
            value: amount,
            script_pubkey: bitcoin::ScriptBuf::new(),
        })
        .take(shape.n_outputs)
        .collect(),
    };
    (credit, spend)
}

/// One Core `script_tests` witness string (`#SCRIPT#`, `#CONTROLBLOCK#`, or hex).
pub fn push_core_witness_token(
    stack: &mut Vec<Vec<u8>>,
    tap_out: &mut Option<[u8; 32]>,
    token: &str,
) -> Result<(), String> {
    if token.is_empty() {
        stack.push(vec![]);
        return Ok(());
    }
    if let Some(rest) = token.strip_prefix("#SCRIPT#") {
        stack.push(assemble_script(rest.trim())?);
        return Ok(());
    }
    if token == "#CONTROLBLOCK#" {
        let leaf = stack
            .last()
            .ok_or_else(|| "#CONTROLBLOCK# without leaf script".to_string())?
            .clone();
        let (control, output) = taproot_leaf_control(&leaf)?;
        stack.push(control);
        *tap_out = Some(output);
        return Ok(());
    }
    let hex = token.trim_start_matches("0x").trim_start_matches("0X");
    if !hex.len().is_multiple_of(2) {
        return Err(format!("odd witness hex: {token}"));
    }
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("witness is not hex: {token}"));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for j in (0..hex.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&hex[j..j + 2], 16).map_err(|e| e.to_string())?);
    }
    stack.push(bytes);
    Ok(())
}
