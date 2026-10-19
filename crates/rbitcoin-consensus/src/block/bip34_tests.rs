//! bip34_tests (peeled from block.rs).

use super::bip34_height_script;

#[test]
// btc-lean: BLK-069 BLK-070 INV-103
fn small_heights_use_op_n() {
    assert_eq!(bip34_height_script(0), vec![0x00]);
    for h in 1u32..=16 {
        assert_eq!(bip34_height_script(h), vec![0x50 + h as u8]);
    }
}

#[test]
fn height_17_uses_push() {
    assert_eq!(bip34_height_script(17), vec![0x01, 0x11]);
}

#[test]
fn height_128_sign_byte() {
    // 128 = 0x80 needs trailing 0x00 so it is not negative
    assert_eq!(bip34_height_script(128), vec![0x02, 0x80, 0x00]);
}

#[test]
fn multi_byte_pad_and_256() {
    assert_eq!(bip34_height_script(255), vec![0x02, 0xff, 0x00]);
    assert_eq!(bip34_height_script(256), vec![0x02, 0x00, 0x01]);
}

#[test]
fn kill_bip34_remaining_edges() {
    // 32768 = 0x8000 -> little endian 0x00 0x80, high bit set -> needs 0x00 pad
    // tests high-bit pad path: last & 0x80!=0 => push 0x00
    assert_eq!(bip34_height_script(32768), vec![0x03, 0x00, 0x80, 0x00]);
    // 700k = real mainnet height, 3 bytes, last byte 0x0a no pad
    assert_eq!(bip34_height_script(700_000), vec![0x03, 0x60, 0xae, 0x0a]);
    // 128 vs 127 distinction kills & with | at last & 0x80
    assert_ne!(bip34_height_script(127), bip34_height_script(128));
}
