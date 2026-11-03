use rbitcoin_net::versionbits_warn::*;
use rbitcoin_primitives::{Height, Network};
use rbitcoin_query::Query;

/// Core `WarningBitsConditionChecker`: mainnet keeps 1815 of 2016 (BIP
/// 341's 90%), test chains take 75% of the difficulty interval, and each
/// chain counts from its `MinBIP9WarningHeight`.
#[test]
fn warn_rule_matches_core_chainparams() {
    let rule = |n| (warn_period_threshold(n), warn_min_height(n));
    assert_eq!(rule(Network::Mainnet), ((2016, 1815), 711_648));
    assert_eq!(rule(Network::Testnet), ((2016, 1512), 2_013_984));
    assert_eq!(rule(Network::Signet), ((2016, 1512), 0));
    assert_eq!(rule(Network::Testnet4), ((2016, 1512), 0));
    assert_eq!(rule(Network::Regtest), ((144, 108), 0));
}

#[test]
fn warning_text_matches_core() {
    assert_eq!(
        unknown_rules_warning(27),
        "Unknown new rules activated (versionbit 27)"
    );
}

#[test]
fn top_bits_signal_detection() {
    let v = (VERSIONBITS_TOP_BITS | (1 << 27)) as i32;
    assert!(signals_unknown(&v, 27));
    assert!(!signals_unknown(&v, 26));
    assert!(!signals_unknown(&(VERSIONBITS_TOP_BITS as i32), 27));
}

/// Regtest-shaped chain of `n` headers; heights in `signal` set `mask`.
fn put_chain(q: &Query, n: u32, signal: impl Fn(u32) -> bool, salt: u8, mask: u32) {
    use rbitcoin_primitives::Fk;
    use rbitcoin_store::HeaderRecord;
    let mut prev_fk = Fk::NULL;
    let mut prev_hash = [0u8; 32];
    for h in 0u32..n {
        let mut merkle = [salt; 32];
        merkle[0..4].copy_from_slice(&h.to_le_bytes());
        let version = if h > 0 && signal(h) {
            (VERSIONBITS_TOP_BITS | mask) as i32
        } else {
            1
        };
        let hash = if h == 0 {
            merkle
        } else {
            rbitcoin_store::block_header_hash(version, &prev_hash, &merkle, h + 1, 0x207fffff, h)
        };
        let rec = HeaderRecord {
            prev_fk,
            version,
            timestamp: h + 1,
            bits: 0x207fffff,
            nonce: h,
            merkle_root: merkle,
            hash,
            size: 0,
            weight: 0,
        };
        prev_fk = q.put_header(&rec).unwrap();
        q.store()
            .confirmed
            .set(&rbitcoin_store::ClassCWrite::for_test(), Height(h), prev_fk)
            .unwrap();
        prev_hash = hash;
    }
    q.store().rebuild_height_fence().unwrap();
}

/// Activation needs a signalling period plus one more; only blocks at or
/// above the floor count (so mainnet's CSV, SegWit and Taproot periods
/// raise no warning); the scan keeps its place across calls
/// (`getnetworkinfo` used to re-read every header per bit, ≈4.7 s on
/// mainnet) and starts over when the boundary changes.
#[test]
fn unknown_bit_scan_activates_and_keeps_its_place() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("vb-active");
    assert!(UnknownBitsScan::new().advance(&q, 0, 4, 2, 0).is_empty());
    assert!(UnknownBitsScan::new().advance(&q, 4, 4, 2, 0).is_empty());

    put_chain(&q, 13, |h| h < 4, 0, 1 << 3);
    let mut scan = UnknownBitsScan::new();
    assert_eq!(scan.advance(&q, 8, 4, 2, 0), vec![3]);
    assert_eq!(scan.scanned_periods, 1);
    let (_, boundary) = q.header_at_height(Height(3)).unwrap().unwrap();
    assert_eq!(scan.boundary, boundary.hash, "counted boundary is height 3");
    scan.locked = 0;
    assert!(
        scan.advance(&q, 8, 4, 2, 0).is_empty(),
        "same tip does not reread a finished period"
    );
    assert_eq!(scan.scanned_periods, 1, "same tip: nothing new to read");
    assert!(
        scan.advance(&q, 12, 4, 2, 0).is_empty(),
        "a later period that does not signal stays locked-empty"
    );
    assert_eq!(scan.scanned_periods, 2);
    assert!(UnknownBitsScan::new().advance(&q, 8, 4, 4, 0).is_empty());
    assert_eq!(UnknownBitsScan::new().advance(&q, 8, 4, 2, 2), vec![3]);
    assert!(UnknownBitsScan::new().advance(&q, 8, 4, 2, 3).is_empty());

    // Period 1 signals only at its last two blocks. Threshold 3 stays
    // empty; threshold 2 locks. A wider or shorter window would disagree.
    let (dir3, wide) = rbitcoin_query::testutil::tiny_query_labeled("vb-wide");
    put_chain(&wide, 13, |h| h < 4 || h == 6 || h == 7, 2, 1 << 3);
    let (_, wide_boundary) = wide.header_at_height(Height(3)).unwrap().unwrap();
    let mut under = UnknownBitsScan::new();
    under.scanned_periods = 1;
    under.boundary = wide_boundary.hash;
    assert!(
        under.advance(&wide, 12, 4, 3, 0).is_empty(),
        "two signals in period 1 are under threshold 3"
    );
    let mut over = UnknownBitsScan::new();
    over.scanned_periods = 1;
    over.boundary = wide_boundary.hash;
    assert_eq!(over.advance(&wide, 12, 4, 2, 0), vec![3]);

    let (dir2, other) = rbitcoin_query::testutil::tiny_query_labeled("vb-other");
    put_chain(&other, 9, |_| false, 1, 1 << 3);
    assert!(
        scan.advance(&other, 8, 4, 2, 0).is_empty(),
        "a different header at the counted boundary starts over"
    );
    assert_eq!(scan.scanned_periods, 1);
    let (dir4, both) = rbitcoin_query::testutil::tiny_query_labeled("vb-both");
    put_chain(&both, 13, |h| h < 4, 4, (1 << 3) | (1 << 27));
    assert_eq!(
        UnknownBitsScan::new().advance(&both, 8, 4, 2, 0),
        vec![3],
        "bit 27 is outside the BIP 323 window"
    );
    let (dir5, high) = rbitcoin_query::testutil::tiny_query_labeled("vb-high");
    put_chain(&high, 13, |h| h < 4, 5, 1 << 27);
    assert!(
        UnknownBitsScan::new().advance(&high, 8, 4, 2, 0).is_empty(),
        "a reserved bit does not warn"
    );
    let (dir6, ignored) = rbitcoin_query::testutil::tiny_query_labeled("vb-bit5");
    put_chain(&ignored, 13, |h| h < 4, 6, 1 << 5);
    assert!(
        UnknownBitsScan::new()
            .advance(&ignored, 8, 4, 2, 0)
            .is_empty(),
        "bit 5 is reserved"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
    let _ = std::fs::remove_dir_all(&dir3);
    let _ = std::fs::remove_dir_all(&dir4);
    let _ = std::fs::remove_dir_all(&dir5);
    let _ = std::fs::remove_dir_all(&dir6);
}
