use rbitcoin_primitives::*;

#[test]
fn fk_display_and_get() {
    assert!(Fk::NULL.is_null());
    assert_eq!(Fk::NULL.get(), None);
    assert_eq!(format!("{}", Fk::NULL), "Fk(null)");
    assert_eq!(Fk::new(0), None);
    let f = Fk::new(7).unwrap();
    assert_eq!(f.get(), Some(7));
    assert_eq!(format!("{f}"), "Fk(7)");
}

#[test]
fn height_display_and_next() {
    assert_eq!(Height::GENESIS.0, 0);
    assert_eq!(format!("{}", Height(42)), "42");
    assert_eq!(Height(u32::MAX).next(), None);
    assert_eq!(Height(0).next(), Some(Height(1)));
}

#[test]
fn network_parse_display_and_error() {
    assert_eq!(Network::parse("mainnet").unwrap(), Network::Mainnet);
    assert_eq!(Network::parse("TESTNET3").unwrap(), Network::Testnet);
    assert_eq!(Network::parse("signet").unwrap().as_str(), "signet");
    assert_eq!(format!("{}", Network::Regtest), "regtest");
    let err = Network::parse("bogus").unwrap_err();
    assert_eq!(format!("{err}"), "unknown network `bogus`");
    let _ = &err as &dyn std::error::Error;
    assert_eq!(Network::Mainnet.default_p2p_port(), 8333);
    assert_eq!(Network::Mainnet.default_rpc_port(), 8332);
    assert_eq!(Network::Testnet.default_p2p_port(), 18333);
    assert_eq!(Network::Testnet.default_rpc_port(), 18332);
    assert_eq!(Network::Signet.default_p2p_port(), 38333);
    assert_eq!(Network::Signet.default_rpc_port(), 38332);
    assert_eq!(Network::Regtest.default_p2p_port(), 18444);
    assert_eq!(Network::Regtest.default_rpc_port(), 18443);
    let t4 = Network::parse("testnet4").unwrap();
    assert_eq!(t4.as_str(), "testnet4");
    assert_eq!(t4.default_p2p_port(), 48333);
    assert_eq!(t4.default_rpc_port(), 48332);
    assert_eq!(DEFAULT_ELECTRUM_PORT, 50001);
    assert_eq!(DEFAULT_ESPLORA_PORT, 3000);
}

#[test]
fn table_kind_roundtrip() {
    for v in [
        1u16, 2, 3, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    ] {
        let k = TableKind::from_u16(v).expect("kind");
        assert_eq!(k.as_u16(), v);
    }
    assert!(TableKind::from_u16(4).is_none());
    assert!(TableKind::from_u16(5).is_none());
    assert!(TableKind::from_u16(6).is_none());
    assert!(TableKind::from_u16(12).is_none());
    assert!(TableKind::from_u16(0).is_none());
    assert!(TableKind::from_u16(99).is_none());
    assert_eq!(TableKind::TxOut.as_u16(), 3);
    assert_eq!(TableKind::Spender.as_u16(), 13);
    assert_eq!(TableKind::TxidBody.as_u16(), 14);
    assert_eq!(TableKind::SpTweaks.as_u16(), 15);
    assert_eq!(TableKind::SeqSigWit.as_u16(), 16);
    assert_eq!(TableKind::Spent.as_u16(), 17);
    assert_eq!(TableKind::DeltaLoc.as_u16(), 18);
    assert_eq!(TableKind::TxStat.as_u16(), 19);
    assert_eq!(TableKind::TxStatOvf.as_u16(), 20);
    assert_eq!(TableKind::TxStatBlk.as_u16(), 21);
    assert_eq!(TableKind::Input.as_u16(), 22);
    assert_eq!(TableKind::InputLoc.as_u16(), 23);
    assert_eq!(TableKind::from_u16(24), Some(TableKind::BlockFilter));
}

#[test]
fn schema_file_openable_is_22_through_current() {
    assert!(!schema_file_openable(21));
    assert!(!schema_file_openable(13));
    assert!(schema_file_openable(22));
    assert!(schema_file_openable(SCHEMA_VERSION));
    assert!(!schema_file_openable(SCHEMA_VERSION + 1));
    eprintln!(
        "schema_file_openable false below 22 (21={} 13={}) true from 22 through current {} (22={} current={})",
        schema_file_openable(21),
        schema_file_openable(13),
        SCHEMA_VERSION,
        schema_file_openable(22),
        schema_file_openable(SCHEMA_VERSION)
    );
}

#[test]
fn constants_stable() {
    assert_eq!(STORE_MAGIC, *b"RBT1");
    assert_eq!(SCHEMA_VERSION, 26);
    assert!(!VERSION.is_empty());
    assert!(schema_file_openable(26));
    assert!(schema_file_openable(25));
    assert!(schema_file_openable(24));
    assert!(schema_file_openable(23));
    assert!(schema_file_openable(22));
    assert!(!schema_file_openable(21));
    assert!(!schema_file_openable(20));
    assert!(!schema_file_openable(16));
    assert!(!schema_file_openable(13));
    assert!(!schema_file_openable(12));
    assert!(!schema_file_openable(27));
    assert!(!schema_file_openable(0));
}

#[test]
fn subversion_comments_and_rejects() {
    assert_eq!(
        rbitcoin_subversion("0.1.0", &[] as &[&str]).unwrap(),
        "/rbitcoin:0.1.0/"
    );
    let s = rbitcoin_subversion("0.1.0", &["testnode0"]).unwrap();
    assert_eq!(s, "/rbitcoin:0.1.0(testnode0)/");
    assert_eq!(&s[s.len() - 12..s.len() - 1], "(testnode0)");
    let s = rbitcoin_subversion("0.1.0", &["testnode0", "foo"]).unwrap();
    assert_eq!(s, "/rbitcoin:0.1.0(testnode0; foo)/");
    assert!(rbitcoin_subversion("0.1.0", &["a/b"])
        .unwrap_err()
        .contains("unsafe"));
    assert!(rbitcoin_subversion("0.1.0", &["a".repeat(256)])
        .unwrap_err()
        .contains("exceeds maximum"));
}

#[test]
fn live_version_feeds_subversion() {
    assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
    let s = rbitcoin_subversion(VERSION, &[] as &[&str]).unwrap();
    assert_eq!(s, format!("/rbitcoin:{VERSION}/"));
}
