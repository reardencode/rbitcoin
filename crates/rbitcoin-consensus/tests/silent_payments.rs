use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::script::Script;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{OutPoint, Transaction, TxOut, Witness};
use rbitcoin_consensus::silent_payments::*;

use bitcoin::script::ScriptBuf;

use bitcoin::transaction::Version as TxVersion;
use bitcoin::{Amount, Sequence, TxIn};
use serde_json::Value;
use std::str::FromStr;
#[test]
fn classifier_edges() {
    let p2wpkh = {
        let mut v = vec![0x00, 0x14];
        v.extend(std::iter::repeat_n(0x11, 20));
        v
    };
    let ver = |spk: &[u8]| {
        Script::from_bytes(spk)
            .witness_version()
            .map(|v| v.to_num())
    };
    assert_eq!(ver(&p2wpkh), Some(0));
    assert_eq!(ver(&[0x00, 0x02, 0xaa, 0xbb]), Some(0));
    assert_eq!(ver(&[0x00, 0x14, 0x11, 0x11, 0x11]), None);
    assert_eq!(ver(&[0x00, 40, 0x22]), None);
    let mut v1 = vec![0x51, 0x20];
    v1.extend(std::iter::repeat_n(0x33, 32));
    assert_eq!(ver(&v1), Some(1));
    let mut v2 = vec![0x52, 0x20];
    v2.extend(std::iter::repeat_n(0x33, 32));
    assert_eq!(ver(&v2), Some(2));

    let mut short_cb = vec![0x01];
    short_cb.extend(std::iter::repeat_n(0x44, 31));
    let short = Witness::from_slice(&[vec![0x51], short_cb]);
    assert!(!nums_h_script_path(&short));
    let mut nums = vec![0xc0];
    nums.extend_from_slice(&NUMS_H);
    let path = Witness::from_slice(&[vec![0x51], nums]);
    assert!(nums_h_script_path(&path));

    let push = |payload: &[u8]| {
        let mut s = vec![payload.len() as u8];
        s.extend_from_slice(payload);
        ScriptBuf::from_bytes(s)
    };
    assert!(is_p2sh_p2wpkh_redeem(push(&p2wpkh).as_script()));
    let mut not_ver = p2wpkh.clone();
    not_ver[0] = 0x01;
    assert!(!is_p2sh_p2wpkh_redeem(push(&not_ver).as_script()));
    assert!(!is_p2sh_p2wpkh_redeem(push(&[0x51; 22]).as_script()));
    let mut not_prog = p2wpkh.clone();
    not_prog[1] = 0x15;
    assert!(!is_p2sh_p2wpkh_redeem(push(&not_prog).as_script()));

    let sk = SecretKey::from_slice(&[3u8; 32]).unwrap();
    let pk = PublicKey::from_secret_key(secp(), &sk);
    let mut tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([9u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes({
                let mut s = vec![0x51, 0x20];
                s.extend(std::iter::repeat_n(0xab, 32));
                s
            }),
        }],
    };
    tx.input.push(TxIn {
        previous_output: OutPoint {
            txid: bitcoin::Txid::from_byte_array([0u8; 32]),
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    });
    let hashed = input_hash_mul_a(&tx, &pk);
    tx.input.swap(0, 1);
    assert_eq!(input_hash_mul_a(&tx, &pk), hashed);
}

#[test]
fn taproot_matches_scan_rejects_invalid_tweak() {
    let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
    let pk = PublicKey::from_secret_key(secp(), &sk);
    let outputs = [TaprootOut {
        vout: 0,
        xonly: [0u8; 32],
        value: 1,
    }];
    assert!(!taproot_matches_scan(&[0u8; 33], &outputs, &sk, &[pk]));
    assert!(!taproot_matches_scan(&[2u8; 33], &outputs, &sk, &[pk]));
    assert!(!taproot_matches_scan(&pk.serialize(), &[], &sk, &[pk]));
    assert!(!taproot_matches_scan(&pk.serialize(), &outputs, &sk, &[]));
}

fn hex_bytes(s: &str) -> Vec<u8> {
    rbitcoin_primitives::hex_decode(s).expect("hex")
}

fn decode_witness(s: &str) -> Witness {
    if s.is_empty() {
        return Witness::new();
    }
    let b = hex_bytes(s);
    deserialize::<Witness>(&b).unwrap_or_else(|_| Witness::from_slice(&[&b]))
}

fn tx_from_receiving(given: &Value) -> (Transaction, Vec<TxOut>) {
    let vin = given["vin"].as_array().expect("vin");
    let mut input = Vec::new();
    let mut prevouts = Vec::new();
    for v in vin {
        let txid = bitcoin::Txid::from_str(v["txid"].as_str().unwrap()).unwrap();
        let vout = v["vout"].as_u64().unwrap() as u32;
        let script_sig = ScriptBuf::from_bytes(hex_bytes(v["scriptSig"].as_str().unwrap_or("")));
        let wit = match &v["txinwitness"] {
            Value::String(s) => decode_witness(s),
            Value::Array(items) => {
                let stacks: Vec<Vec<u8>> = items
                    .iter()
                    .filter_map(|x| x.as_str().map(hex_bytes))
                    .collect();
                let refs: Vec<&[u8]> = stacks.iter().map(|s| s.as_slice()).collect();
                Witness::from_slice(&refs)
            }
            _ => Witness::new(),
        };
        input.push(TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig,
            sequence: Sequence::MAX,
            witness: wit,
        });
        let prev_hex = v["prevout"]["scriptPubKey"]["hex"].as_str().unwrap();
        prevouts.push(TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(hex_bytes(prev_hex)),
        });
    }
    let mut output = Vec::new();
    if let Some(outs) = given["outputs"].as_array() {
        for o in outs {
            let x = hex_bytes(o.as_str().unwrap());
            assert_eq!(x.len(), 32);
            let mut spk = vec![0x51, 0x20];
            spk.extend_from_slice(&x);
            output.push(TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(spk),
            });
        }
    }
    if output.is_empty() {
        output.push(TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes({
                let mut s = vec![0x51, 0x20];
                s.extend_from_slice(&[0u8; 32]);
                s
            }),
        });
    }
    (
        Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input,
            output,
        },
        prevouts,
    )
}

#[test]
fn official_vectors_receiving_tweaks() {
    let raw = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/bip352_send_and_receive_test_vectors.json"
    ));
    let cases: Value = serde_json::from_str(raw).expect("vectors json");
    let mut n = 0u32;
    for case in cases.as_array().unwrap() {
        let comment = case["comment"].as_str().unwrap_or("");
        for rec in case["receiving"].as_array().unwrap() {
            let given = &rec["given"];
            let expected = &rec["expected"];
            let (tx, prev) = tx_from_receiving(given);
            let got = tweak_from_tx(&tx, &prev);
            match expected.get("tweak") {
                Some(Value::String(exp)) => {
                    let t = got.unwrap_or_else(|| panic!("expected tweak for {comment}"));
                    assert_eq!(
                        rbitcoin_primitives::hex_encode(t.tweak),
                        exp.to_ascii_lowercase(),
                        "tweak mismatch: {comment}"
                    );
                    n += 1;
                }
                _ => {
                    assert!(
                        got.is_none(),
                        "expected skip for {comment}, got {:?}",
                        got.map(|g| rbitcoin_primitives::hex_encode(g.tweak))
                    );
                    n += 1;
                }
            }
            let unlabeled = given["labels"]
                .as_array()
                .map(|a| a.is_empty())
                .unwrap_or(true);
            if unlabeled {
                if let Some(scan_hex) = given["key_material"]["scan_priv_key"].as_str() {
                    if let Some(tweak_hex) = expected["tweak"].as_str() {
                        let scan = SecretKey::from_slice(&hex_bytes(scan_hex)).unwrap();
                        let spend_sk = SecretKey::from_slice(&hex_bytes(
                            given["key_material"]["spend_priv_key"].as_str().unwrap(),
                        ))
                        .unwrap();
                        let spend_pk = PublicKey::from_secret_key(secp(), &spend_sk);
                        let mut tw = [0u8; 33];
                        tw.copy_from_slice(&hex_bytes(tweak_hex));
                        if let Some(outs) = expected["outputs"].as_array() {
                            for o in outs {
                                let Some(pk) = o["pub_key"].as_str() else {
                                    continue;
                                };
                                let mut x = [0u8; 32];
                                x.copy_from_slice(&hex_bytes(pk));
                                assert!(
                                    taproot_matches_scan(
                                        &tw,
                                        &[TaprootOut {
                                            vout: 0,
                                            xonly: x,
                                            value: 1
                                        }],
                                        &scan,
                                        &[spend_pk],
                                    ),
                                    "scan miss {comment}"
                                );
                                n += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(n >= 28, "ran {n} receiving cases");
}

#[test]
fn skip_witness_v2_input() {
    let tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes({
                let mut s = vec![0x51, 0x20];
                s.extend_from_slice(&[1u8; 32]);
                s
            }),
        }],
    };
    let mut v2 = vec![0x52, 0x14];
    v2.extend_from_slice(&[0u8; 20]);
    let prev = vec![TxOut {
        value: Amount::from_sat(1),
        script_pubkey: ScriptBuf::from_bytes(v2),
    }];
    assert!(tweak_from_tx(&tx, &prev).is_none());
}
