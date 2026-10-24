use rbitcoin_consensus::script::crypto::{
    is_compressed_or_uncompressed_pubkey, is_compressed_pubkey, is_defined_hashtype,
    is_valid_signature_encoding, parse_der_sig,
};

fn valid_der_sig() -> Vec<u8> {
    // Minimal valid-shaped DER + SIGHASH_ALL
    // 30 06 02 01 01 02 01 01 01
    vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]
}

#[test]
fn strictenc_pubkey_and_hashtype_helpers() {
    // Compressed / uncompressed only — hybrid 06/07 rejected.
    assert!(is_compressed_or_uncompressed_pubkey(&[0x02; 33]));
    assert!(is_compressed_or_uncompressed_pubkey(&[0x03; 33]));
    let mut uncomp = vec![0x04];
    uncomp.extend_from_slice(&[0x11; 64]);
    assert!(is_compressed_or_uncompressed_pubkey(&uncomp));
    let mut hybrid = vec![0x06];
    hybrid.extend_from_slice(&[0x11; 64]);
    assert!(!is_compressed_or_uncompressed_pubkey(&hybrid));
    assert!(!is_compressed_or_uncompressed_pubkey(&[]));
    assert!(!is_compressed_or_uncompressed_pubkey(&[0x02; 32]));
    // `0x04` is uncompressed only at 65 bytes. A shorter key is not
    // accepted by dropping the length guard.
    assert!(!is_compressed_or_uncompressed_pubkey(&[0x04; 64]));
    assert!(!is_compressed_or_uncompressed_pubkey(&[0x04; 66]));
    assert!(is_compressed_pubkey(&[0x02; 33]));
    assert!(!is_compressed_pubkey(&[0x02; 32]));
    assert!(!is_compressed_pubkey(&[0x04; 33]));

    assert!(is_defined_hashtype(&[0x30, 0x01])); // ALL
    assert!(is_defined_hashtype(&[0x30, 0x02])); // NONE
    assert!(is_defined_hashtype(&[0x30, 0x03])); // SINGLE
    assert!(is_defined_hashtype(&[0x30, 0x81])); // ALL|ACP
    assert!(!is_defined_hashtype(&[0x30, 0x00]));
    assert!(!is_defined_hashtype(&[0x30, 0x04]));
    assert!(!is_defined_hashtype(&[]));
}

#[test]
fn bip66_encoding_edge_cases() {
    assert!(!is_valid_signature_encoding(&[]));
    assert!(!is_valid_signature_encoding(&[0x30; 8])); // too short
    assert!(!is_valid_signature_encoding(&[0x30; 74])); // too long
    let mut bad = valid_der_sig();
    bad[0] = 0x31;
    assert!(!is_valid_signature_encoding(&bad));
    // wrong total length byte
    let mut bad = valid_der_sig();
    bad[1] = 0x05;
    assert!(!is_valid_signature_encoding(&bad));
    // R not INT
    let mut bad = valid_der_sig();
    bad[2] = 0x03;
    assert!(!is_valid_signature_encoding(&bad));
    // zero-length R
    assert!(!is_valid_signature_encoding(&[
        0x30, 0x06, 0x02, 0x00, 0x02, 0x01, 0x01, 0x01
    ]));
    // R high bit set (negative)
    let neg = vec![0x30, 0x07, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01, 0x01];
    assert!(!is_valid_signature_encoding(&neg));
    // excess leading zero on R
    let pad = vec![0x30, 0x08, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01, 0x01];
    assert!(!is_valid_signature_encoding(&pad));
    // S high bit
    let sneg = vec![0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x80, 0x01];
    assert!(!is_valid_signature_encoding(&sneg));
    // excess leading zero on S
    let spad = vec![0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x01, 0x01];
    assert!(!is_valid_signature_encoding(&spad));
    // zero-length S
    assert!(!is_valid_signature_encoding(&[
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x00, 0x01
    ]));
    // S marker wrong
    let mut sm = valid_der_sig();
    sm[4] = 0x03; // after R len=1 at [3]=1, S tag at index 4
                  // structure: [0]=30 [1]=06 [2]=02 [3]=01 [4]=R [5]=02 [6]=01 [7]=S [8]=ht
                  // Actually valid_der is 30 06 02 01 01 02 01 01 01 so S tag at [5]
    let mut sm = valid_der_sig();
    sm[5] = 0x03;
    assert!(!is_valid_signature_encoding(&sm));

    assert!(is_valid_signature_encoding(&valid_der_sig()));
    // BIP66 does not range-check the hashtype byte. STRICTENC does,
    // via `is_defined_hashtype`. `0x00`, `0x04`, `0x80`, and `0x85`
    // stay valid DER.
    for ht in [0x00u8, 0x04, 0x80, 0x85] {
        let mut sig = valid_der_sig();
        let last = sig.len() - 1;
        sig[last] = ht;
        assert!(
            is_valid_signature_encoding(&sig),
            "BIP66 keeps hashtype {ht:#x}"
        );
        assert!(
            !is_defined_hashtype(&sig),
            "STRICTENC rejects hashtype {ht:#x}"
        );
    }
    // A one-byte zero integer is minimal. `len > 1` must not become `>=`.
    assert!(is_valid_signature_encoding(&[
        0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x01
    ]));
    assert!(is_valid_signature_encoding(&[
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x01
    ]));
    let _ = (neg, pad, sneg, spad);
}

#[test]
fn parse_der_empty_and_strict() {
    assert!(parse_der_sig(&[], true).is_err());
    // non-BIP66 but lax may still fail parse — just exercise strict reject
    let bad = vec![0x30, 0x01, 0x00];
    assert!(parse_der_sig(&bad, true).is_err());
}
