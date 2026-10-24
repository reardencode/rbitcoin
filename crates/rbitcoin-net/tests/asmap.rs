use rbitcoin_net::asmap::*;
use std::net::IpAddr;
use std::net::Ipv4Addr;

#[test]
fn asmap_rejected_bytecodes_fail_sanity() {
    for bytes in [
        ASMAP_SECOND_DEFAULT,
        ASMAP_TRAILING_ONE,
        ASMAP_EIGHT_TRAILING_ZEROS,
        ASMAP_TWO_SHORT_MATCHES,
        ASMAP_MATCH_PAST_END,
        ASMAP_JUMP_PAST_FILE,
        ASMAP_JUMP_SHORT_TAIL,
        ASMAP_JUMP_OFF_END,
        &[],
        &[0],
    ] {
        assert!(
            AsMap::from_bytes(bytes.to_vec()).is_none(),
            "accepted {bytes:?}"
        );
    }
}

#[test]
fn asmap_two_prefix_const_matches_encoder() {
    assert_eq!(two_prefix_asmap_bytes(), TWO_PREFIX_ASMAP);
}

#[test]
fn asmap_fuzz_seed_fixture_is_two_prefix_then_ip16() {
    const SEED: &[u8] = include_bytes!("../tests/fixtures/asmap_two_prefix_plus_ip.bin");
    assert!(SEED.len() > 16, "asmap then leftover ip16");
    let (asmap, ip) = SEED.split_at(SEED.len() - 16);
    assert_eq!(asmap, TWO_PREFIX_ASMAP);
    let m = AsMap::from_bytes(asmap.to_vec()).expect("two-prefix");
    let mut ip16 = [0u8; 16];
    ip16.copy_from_slice(ip);
    assert_eq!(m.interpret_ip16(&ip16), 1);
    assert_eq!(ip16, ip16_for_lookup(IpAddr::V4(Ipv4Addr::new(1, 2, 0, 0))));
}
