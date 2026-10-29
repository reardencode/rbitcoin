use bitcoin::key::XOnlyPublicKey;
use bitcoin::opcodes::all::OP_CHECKMULTISIG;
use bitcoin::opcodes::{Class, ClassifyContext};
use bitcoin::script::Instruction;
use bitcoin::{Address, Network, Script};
use rbitcoin_primitives::hex_encode;

const MAX_MULTISIG_KEYS: usize = 20;

pub fn infer_descriptor(script: &Script, network: Network) -> String {
    let body = infer_body(script, network);
    let sum = checksum(&body);
    format!("{body}#{sum}")
}

fn infer_body(script: &Script, network: Network) -> String {
    if let Some(key) = p2pk_key(script).filter(|key| !is_hybrid(key)) {
        return format!("pk({})", hex_encode(key));
    }
    if let Some((required, keys)) =
        bare_multisig(script).filter(|(_, keys)| !keys.iter().any(|k| is_hybrid(k)))
    {
        let keys: Vec<String> = keys.into_iter().map(hex_encode).collect();
        return format!("multi({required},{})", keys.join(","));
    }
    if let Some(key) = taproot_output_key(script) {
        return format!("rawtr({})", hex_encode(key.serialize()));
    }
    if let Ok(addr) = Address::from_script(script, network) {
        return format!("addr({addr})");
    }
    format!("raw({})", hex_encode(script.as_bytes()))
}

fn has_key_size(push: &[u8]) -> bool {
    let want = match push.first() {
        Some(2 | 3) => 33,
        Some(4 | 6 | 7) => 65,
        _ => return false,
    };
    push.len() == want
}

fn is_hybrid(key: &[u8]) -> bool {
    matches!(key.first(), Some(6 | 7))
}

pub(super) fn p2pk_key(script: &Script) -> Option<&[u8]> {
    let b = script.as_bytes();
    let (&len, rest) = b.split_first()?;
    let (&last, key) = rest.split_last()?;
    let sized = (len == 33 || len == 65) && key.len() == usize::from(len);
    (sized && last == rbitcoin_primitives::OP_CHECKSIG && has_key_size(key)).then_some(key)
}

pub(super) fn bare_multisig(script: &Script) -> Option<(usize, Vec<&[u8]>)> {
    let b = script.as_bytes();
    let mut ops = script.instruction_indices();
    let (at, first) = ops.next()?.ok()?;
    let required = multisig_count(b, at, first, 1)?;
    let mut keys = Vec::new();
    let (at, count) = loop {
        let (at, ins) = ops.next()?.ok()?;
        match ins {
            Instruction::PushBytes(p) if has_key_size(p.as_bytes()) => keys.push(p.as_bytes()),
            other => break (at, other),
        }
    };
    if multisig_count(b, at, count, required)? != keys.len() {
        return None;
    }
    let (_, last) = ops.next()?.ok()?;
    if last != Instruction::Op(OP_CHECKMULTISIG) || ops.next().is_some() {
        return None;
    }
    Some((required, keys))
}

fn multisig_count(script: &[u8], at: usize, ins: Instruction<'_>, min: usize) -> Option<usize> {
    let n = match ins {
        Instruction::Op(op) => match op.classify(ClassifyContext::Legacy) {
            Class::PushNum(n) => usize::try_from(n).ok()?,
            _ => return None,
        },
        Instruction::PushBytes(p) => match (script[at], p.as_bytes()) {
            (1, &[n]) if n > 16 => usize::from(n),
            _ => return None,
        },
    };
    (min..=MAX_MULTISIG_KEYS).contains(&n).then_some(n)
}

fn taproot_output_key(script: &Script) -> Option<XOnlyPublicKey> {
    if !script.is_p2tr() {
        return None;
    }
    XOnlyPublicKey::from_slice(&script.as_bytes()[2..]).ok()
}

const INPUT_CHARSET: &str = "0123456789()[],'/*abcdefgh@:$%{}\
IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~\
ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(c: u64, val: u64) -> u64 {
    const GENERATOR: [u64; 5] = [
        0xf5dee51989,
        0xa9fdca3312,
        0x1bab10e32d,
        0x3706b1677a,
        0x644d626ffd,
    ];
    let c0 = c >> 35;
    let mut c = ((c & 0x7_ffff_ffff) << 5) ^ val;
    for (i, g) in GENERATOR.iter().enumerate() {
        if c0 & (1 << i) != 0 {
            c ^= g;
        }
    }
    c
}

fn checksum(body: &str) -> String {
    let mut c = 1u64;
    let mut class = 0u64;
    let mut class_count = 0;
    for ch in body.chars() {
        let pos = INPUT_CHARSET
            .find(ch)
            .expect("inferred descriptor uses only the BIP380 charset") as u64;
        c = polymod(c, pos & 31);
        class = class * 3 + (pos >> 5);
        class_count += 1;
        if class_count == 3 {
            c = polymod(c, class);
            class = 0;
            class_count = 0;
        }
    }
    if class_count > 0 {
        c = polymod(c, class);
    }
    for _ in 0..8 {
        c = polymod(c, 0);
    }
    c ^= 1;
    (0..8)
        .map(|i| char::from(CHECKSUM_CHARSET[((c >> (5 * (7 - i))) & 31) as usize]))
        .collect()
}
