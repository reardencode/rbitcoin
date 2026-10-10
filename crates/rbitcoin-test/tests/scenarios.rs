//! High-level functional scenarios (coverage-bearing).
//!
//! Prefer fewer tests at the highest layer that still hit production paths.
//! Mature regtest chains are built once per test that needs them (not thrice).

use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Block, BlockHash};
use rbitcoin_cli::cli_main as cli_cli_main;
use rbitcoin_consensus::{accept_and_connect_block, genesis_block, ChainParams, Milestone};
use rbitcoin_node::{cli_main as node_cli_main, run_node, NodeConfig};
use rbitcoin_primitives::{Fk, Height, Network, VERSION};
use rbitcoin_query::testutil::FixtureChain;
use rbitcoin_query::{stamp_external_parents, InFlight, Query};
use rbitcoin_store::{HeaderRecord, Store, StoreError, TxRecord};
use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis, spend_anyone_can_spend};
use rbitcoin_test::{
    assert_reconstruct_eq, build_mature_regtest_with_spend, pad_empty_from, TestDatadir,
};
use std::path::PathBuf;
use std::process::{Command, ExitCode};

/// This toolchain's `ExitCode` lacks `PartialEq`; compare via Debug.
fn exit_success(c: ExitCode) -> bool {
    format!("{c:?}") == format!("{:?}", ExitCode::SUCCESS)
}

fn pin_conf_unknown_key_and_peertimeout(td: &TestDatadir) {
    let unknown_dir = td.path().join("from-conf-unknown");
    std::fs::create_dir_all(&unknown_dir).unwrap();
    let unknown_conf = unknown_dir.join("rbitcoin.conf");
    std::fs::write(&unknown_conf, "network=regtest\nunknown_key=1\n").unwrap();
    assert!(
        exit_success(node_cli_main([
            "rbitcoin-node",
            "--datadir",
            unknown_dir.join("data").to_str().unwrap(),
            "--conf",
            unknown_conf.to_str().unwrap(),
            "--smoke",
        ])),
        "unknown conf key must be ignored"
    );

    for (name, body) in [
        ("minrelay-neg", "network=regtest\nmin_relay_tx_fee=-1\n"),
        ("network-nope", "network=nope\n"),
    ] {
        let d = td.path().join(name);
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("rbitcoin.conf");
        std::fs::write(&p, body).unwrap();
        assert!(
            !exit_success(node_cli_main([
                "rbitcoin-node",
                "--datadir",
                d.join("data").to_str().unwrap(),
                "--conf",
                p.to_str().unwrap(),
                "--smoke",
            ])),
            "{name} must fail start"
        );
    }

    assert!(
        exit_success(node_cli_main([
            "rbitcoin-node",
            "--datadir",
            td.path().join("peertimeout-one").to_str().unwrap(),
            "--network",
            "regtest",
            "--peer-timeout",
            "1",
            "--smoke",
        ])),
        "--peer-timeout=1 must smoke"
    );
}

fn node(args: &[&str]) -> ExitCode {
    node_cli_main(std::iter::once("rbitcoin-node").chain(args.iter().copied()))
}

fn exit_is(c: ExitCode, want: u8) -> bool {
    format!("{c:?}") == format!("{:?}", ExitCode::from(want))
}

/// `--smoke` a regtest node under `td/name` with extra argv.
fn smoke(td: &TestDatadir, name: &str, extra: &[&str]) -> ExitCode {
    let d = td.path().join(name);
    let mut args = vec!["--datadir", d.to_str().unwrap(), "--network", "regtest"];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--no-seeds", "--log-level", "error", "--smoke"]);
    node(&args)
}

/// Usage errors exit 2 before a datadir is touched: unknown flags, missing or
/// unparsable values, and every concatenated, one-dash, or Core spelling of a
/// native kebab flag.
fn pin_argv_usage_errors() {
    let refused: &[&[&str]] = &[
        &["--not-a-real-option"],
        &["--datadir"],
        &["--datadir-cold"],
        &["--network"],
        &["--network", "nope"],
        &["--listen"],
        &["--listen", "not-an-addr"],
        &["--connect"],
        &["--connect", "bad host"],
        &["--milestone"],
        &["--milestone", "x"],
        &["--max-outbound"],
        &["--max-outbound", "0"],
        &["--max-outbound", "nope"],
        &["--max-inbound"],
        &["--max-inbound", "nope"],
        &["--mempool-size-mb"],
        &["--mempool-size-mb", "0"],
        &["--mempool-size-mb", "x"],
        &["--max-run-secs"],
        &["--max-run-secs", "x"],
        &["--log-level"],
        &["--log-level", "loud"],
        &["--electrum-listen", "bad"],
        &["--health-listen", "bad"],
        &["--api-log"],
        &["--asmap"],
        &["--conf"],
        &["--conf="],
        &["--sp-tweaks-dust"],
        &["--sp-tweaks-dust", "nope"],
        &["--min-relay-tx-fee", "nope"],
        &["--min-relay-tx-fee", "-0.0001"],
    ];
    for args in refused {
        assert!(exit_is(node(args), 2), "{args:?} must be a usage error");
    }
    for alias in [
        "--chain=regtest",
        "--assumevalid-height=0",
        "--maxconnections=5",
        "--maxmempool=8",
        "--whitelist=noban@127.0.0.1",
        "--blocksonly",
        "--minimumchainwork=0x65",
        "--maxtipage=3600",
        "--uacomment=x",
        "--peertimeout=1",
        "--prefillcompact=0",
        "--limitclustercount=10",
        "--limitclustersize=10",
        "--minrelaytxfee=0.0001",
        "--mempoolexpiry=1",
        "--externalip=1.2.3.4",
        "--seednode=127.0.0.1:1",
        "--mocktime=1",
        "--blockversion=1",
        "--blockmintxfee=0.00000001",
        "--bytespersigop=20",
        "--blockreservedsigops=400",
        "--alertnotify=echo",
        "--startupnotify=echo",
        "--testactivationheight=csv@102",
        "--rpcworkqueue=1",
        "--datadircold=/tmp/x",
        "--electrumlisten=127.0.0.1:1",
        "--esploralisten=127.0.0.1:1",
        "--maxshcreates=1",
        "--esplorablocktemplate=1",
        "--apilog=/tmp/x",
        "--maxrunsecs=1",
        "--inhibitsuspend=1",
        "--rpclisten=127.0.0.1:1",
        "--rpc-user=u",
        "--rpcuser=u",
        "--rpcpassword=p",
        "--checkblocks=6",
        "--blocksdir=/tmp/x",
        "--blocks-dir=/tmp/x",
        "--whitelist-relay=0",
        "--whitelist-forcerelay=1",
        "--shindex",
        "--sptweaks",
        "--sptweaks-dust=1",
        "--pruneseqsigwit",
        "-shindex",
        "-sptweaks",
        "-datadir=/tmp/x",
    ] {
        assert!(exit_is(node(&[alias]), 2), "{alias} must be unknown");
    }
}

/// A conf file that cannot be read or holds a line the node refuses exits 2.
/// Core's `rpcuser` / `rpcpassword` are refused, not ignored: the node
/// authenticates with `rpc.token`.
fn pin_conf_file_refusals(td: &TestDatadir) {
    let missing = td.path().join("missing.conf");
    let d = td.path().join("conf-refused");
    assert!(exit_is(
        node(&["--conf", missing.to_str().unwrap(), "--smoke"]),
        2
    ));
    for (name, body) in [
        ("badlog", "network=regtest\nlog_level=notalevel\n"),
        ("badline", "network=regtest\nnot_a_key_value\n"),
        ("rpcuser", "network=regtest\nrpcuser=u\n"),
        ("rpcpassword", "network=regtest\nrpcpassword=p\n"),
        ("max-outbound-zero", "network=regtest\nmax_outbound=0\n"),
    ] {
        let conf = td.path().join(format!("{name}.conf"));
        std::fs::write(&conf, body).unwrap();
        assert!(
            exit_is(
                node(&[
                    "--conf",
                    conf.to_str().unwrap(),
                    "--datadir",
                    d.to_str().unwrap(),
                    "--smoke",
                ]),
                2
            ),
            "{name} conf must refuse"
        );
    }
    assert!(!d.join("store").exists(), "a refused conf opens no store");
}

/// Flags that parse but describe a node that cannot run exit 1 at validate.
fn pin_validate_refusals(td: &TestDatadir) {
    for (name, args) in [
        ("chainwork-not-hex", &["--min-chain-work=test"][..]),
        ("challenge-off-signet", &["--signet-challenge", "51"]),
        ("tweaks-and-pruning", &["--sp-tweaks", "--prune-seqsigwit"]),
        ("metrics-without-health", &["--metrics"]),
    ] {
        assert!(exit_is(smoke(td, name, args), 1), "{name} must refuse");
    }
    let d = td.path().join("signet-time-no-challenge");
    assert!(exit_is(
        node(&[
            "--datadir",
            d.to_str().unwrap(),
            "--network",
            "signet",
            "--signet-block-time",
            "30",
            "--smoke",
        ]),
        1
    ));
}

/// Operator starts that open a store: native flags, a conf file under CLI
/// overrides, a pruned `--datadir-cold` split, and a custom signet.
fn pin_operator_smokes(td: &TestDatadir) {
    assert!(exit_success(smoke(
        td,
        "native-flags",
        &[
            "--milestone",
            "0",
            "--max-inbound",
            "0",
            "--mempool-size-mb",
            "8",
            "--no-seeds=1",
            "--no-discover",
            "--seed-node",
            "127.0.0.1:8333",
            "--min-relay-tx-fee",
            "0.00000001",
            "--prefill-compact=0",
            "--check-blocks=-1",
            "--sh-index=1",
            "--sp-tweaks",
            "--sp-tweaks-dust=546",
            "--test-activation-height=csv@102",
            "--test-activation-height=dersig@50",
            "--trusted",
            "--limit-cluster-count=10",
            "--min-chain-work=0x65",
        ],
    )));

    // Bare network lines and comments parse. CLI --network and --datadir win
    // over the conf: the store lands under the CLI datadir.
    let conf = td.path().join("bare.conf");
    let conf_data = td.path().join("conf-datadir");
    std::fs::write(
        &conf,
        format!(
            "signet\n# comment\n; also\n\nmax_inbound=0\nmin_relay_tx_fee=0\ndatadir={}\n",
            conf_data.display()
        ),
    )
    .unwrap();
    assert!(exit_success(smoke(
        td,
        "cli-datadir",
        &["--conf", conf.to_str().unwrap()]
    )));
    assert!(td.path().join("cli-datadir").join("store").is_dir());
    assert!(!conf_data.exists(), "CLI --datadir wins over the conf");

    let hot = td.path().join("hot");
    let cold = td.path().join("cold");
    assert!(exit_success(node(&[
        "--datadir",
        hot.to_str().unwrap(),
        "--datadir-cold",
        cold.to_str().unwrap(),
        "--prune-seqsigwit",
        "--prune-seqsigwit-ram-threshold-bytes=4096",
        "--network",
        "regtest",
        "--no-seeds",
        "--log-level",
        "error",
        "--smoke",
    ])));
    assert!(hot.join("store/txout.body").is_file());
    assert!(hot.join("store/seqsigwit.reloc").is_file());
    assert!(!hot.join("store/seqsigwit.body").exists());
    assert!(cold.join("store/seqsigwit.body").is_file());
    assert!(cold.join("store/seqsigwit.loc").is_file());
    assert!(cold.join("store/txstat.body").is_file());
    assert!(cold.join("store/input.body").is_file());
    assert!(!hot.join("store/txstat.body").exists());
    assert!(!hot.join("store/input.body").exists());

    let signet = td.path().join("custom-signet");
    assert!(exit_success(node(&[
        "--datadir",
        signet.to_str().unwrap(),
        "--network",
        "signet",
        "--signet-challenge",
        "51",
        "--signet-block-time",
        "60",
        "--no-seeds",
        "--log-level",
        "error",
        "--smoke",
    ])));
}

// ─── Lifecycle / CLI / surface smoke (collapsed) ────────────────────────────

#[allow(clippy::cognitive_complexity)] // one fixture, many CLI/surface arms
#[test]
fn node_cli_and_surface_smoke() {
    // Networks + run_node lifecycle
    for net in [
        Network::Mainnet,
        Network::Testnet,
        Network::Signet,
        Network::Regtest,
    ] {
        let td = TestDatadir::new().unwrap();
        let cfg = NodeConfig::default()
            .with_datadir(td.path())
            .with_network(net)
            .with_tiny_heads();
        let handle = run_node(cfg).unwrap();
        assert_eq!(handle.network_name(), net.as_str());
        if net == Network::Signet {
            let params = ChainParams::signet();
            let genesis = genesis_block(&params);
            handle.query.enter_direct_index_mode().unwrap();
            accept_and_connect_block(
                &handle.query,
                &params,
                Height::GENESIS,
                &genesis,
                Milestone::NONE,
            )
            .unwrap();
            let (_fk, rec) = handle
                .query
                .header_at_height(Height::GENESIS)
                .unwrap()
                .expect("signet genesis header");
            assert_eq!(rec.hash, genesis.block_hash().to_byte_array());
            assert_eq!(rec.hash, params.genesis_hash.to_byte_array());
            let raw = std::fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../rbitcoin-consensus/tests/fixtures/signet_block_1.bin"),
            )
            .expect("signet_block_1.bin");
            let block1: Block = deserialize(&raw).expect("signet height 1");
            assert_eq!(
                block1.block_hash().to_string(),
                "00000086d6b2636cb2a392d45edc4ec544a10024d30141c9adf4bfd9de533b53"
            );
            accept_and_connect_block(&handle.query, &params, Height(1), &block1, Milestone::NONE)
                .unwrap();
            assert_eq!(handle.query.tip_height(), Some(Height(1)));
        }
        handle.shutdown().unwrap();
    }
    assert!(Network::parse("nope").is_err());
    assert_eq!(Network::parse("REGTEST").unwrap(), Network::Regtest);
    assert!(!VERSION.is_empty());

    // Config errors
    let cfg = NodeConfig {
        datadir: std::path::PathBuf::from("").into(),
        ..NodeConfig::default()
    };
    assert!(run_node(cfg).is_err());
    let td = TestDatadir::new().unwrap();
    let file = td.path().join("blocked");
    std::fs::write(&file, b"nope").unwrap();
    assert!(run_node(NodeConfig::default().with_datadir(file)).is_err());

    // CLI entrypoints
    for net in ["mainnet", "testnet", "signet", "regtest"] {
        let d = td.path().join(net);
        assert!(exit_success(node_cli_main([
            "rbitcoin-node",
            "--datadir",
            d.to_str().unwrap(),
            "--network",
            net,
            "--smoke",
        ])));
    }
    assert!(exit_success(node_cli_main(["rbitcoin-node", "--help"])));
    assert!(exit_success(node_cli_main(["rbitcoin-node", "--version"])));
    assert!(exit_success(node_cli_main(["rbitcoin-node", "-V"])));
    // No node is listening: help and version answer without dialing RPC.
    for arg in ["--help", "-h", "--version", "-V", "help"] {
        assert!(
            exit_success(cli_cli_main(["rbitcoin-cli", arg])),
            "rbitcoin-cli {arg} must not dial"
        );
    }
    assert!(!exit_success(cli_cli_main(["rbitcoin-cli"])));
    assert!(!exit_success(cli_cli_main([
        "rbitcoin-cli",
        "getblockchaininfo"
    ])));
    pin_argv_usage_errors();
    // Electrum without --sh-index still smokes (channel-watch APIs; SH methods fail closed).
    let no_sh = td.path().join("electrum-no-shindex");
    assert!(exit_success(node_cli_main([
        "rbitcoin-node",
        "--datadir",
        no_sh.to_str().unwrap(),
        "--network",
        "regtest",
        "--electrum-listen",
        "127.0.0.1:0",
        "--no-seeds",
        "--milestone",
        "0",
        "--log-level",
        "error",
        "--smoke",
    ])));
    // Happy-path flag combinations (smoke exits after open).
    let flags_ok = td.path().join("flags-ok");
    assert!(exit_success(node_cli_main([
        "rbitcoin-node",
        "--datadir",
        flags_ok.to_str().unwrap(),
        "--network",
        "regtest",
        "--no-seeds",
        "--milestone",
        "0",
        "--max-outbound",
        "2",
        "--mempool-size-mb",
        "32",
        "--max-run-secs",
        "1",
        "--log-level",
        "warn",
        "--listen",
        "127.0.0.1:0",
        "--connect",
        "127.0.0.1:1",
        "--sh-index",
        "--electrum-listen",
        "127.0.0.1:0",
        "--inhibit-suspend",
        "--smoke",
    ])));
    assert!(
        flags_ok.join("store").is_dir(),
        "smoke must create the store under --datadir"
    );
    let flags_off = td.path().join("flags-log-off");
    assert!(exit_success(node_cli_main([
        "rbitcoin-node",
        "--datadir",
        flags_off.to_str().unwrap(),
        "--network",
        "regtest",
        "--log-level",
        "off",
        "--smoke",
    ])));
    let conf_dir = td.path().join("from-conf");
    std::fs::create_dir_all(&conf_dir).unwrap();
    let conf = conf_dir.join("rbitcoin.conf");
    std::fs::write(
        &conf,
        "network=regtest\nmax_outbound=3\nlog_level=warn\nno_seeds=1\n",
    )
    .unwrap();
    assert!(exit_success(node_cli_main([
        "rbitcoin-node",
        "--datadir",
        conf_dir.join("data").to_str().unwrap(),
        "--conf",
        conf.to_str().unwrap(),
        "--smoke",
    ])));
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--datadir",
        td.path().join("peertimeout-zero").to_str().unwrap(),
        "--network",
        "regtest",
        "--peer-timeout",
        "0",
        "--smoke",
    ])));
    pin_conf_unknown_key_and_peertimeout(&td);
    pin_conf_file_refusals(&td);
    pin_validate_refusals(&td);
    pin_operator_smokes(&td);
    assert!(!exit_success(cli_cli_main(["rbitcoin-cli", "a", "b"])));
    for flag in [
        "--rpcuser=u",
        "--rpcpassword=p",
        "--rpcport=1",
        "--rpcconnect=h",
        "-rpcport",
    ] {
        assert!(
            !exit_success(cli_cli_main(["rbitcoin-cli", flag, "getblockcount"])),
            "{flag} must be unknown"
        );
    }

    // Serialize process-wide env mutation (parallel `cargo test` races).
    static DROP_STORE_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());
    {
        let _g = DROP_STORE_ENV.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("RBITCOIN_TEST_DROP_STORE", "1");
        assert!(!exit_success(node_cli_main([
            "rbitcoin-node",
            "--datadir",
            td.path().join("shutdown-fail").to_str().unwrap(),
            "--smoke",
        ])));
        std::env::remove_var("RBITCOIN_TEST_DROP_STORE");
    }

    let node = workspace_bin("rbitcoin-node");
    if node.exists() {
        assert!(Command::new(&node)
            .args([
                "--datadir",
                td.path().join("bin-smoke").to_str().unwrap(),
                "--network",
                "regtest",
                "--smoke",
            ])
            .status()
            .unwrap()
            .success());
    }
}

fn workspace_bin(name: &str) -> std::path::PathBuf {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../target");
    p.push(profile);
    p.push(name);
    p
}

// ─── Store error / corrupt paths (not hit by happy-path chain tests) ────────

#[test]
fn store_error_and_corrupt_paths() {
    let td = TestDatadir::new().unwrap();
    let path = td.store_path();
    let s = Store::create_tiny(&path).unwrap();
    assert!(matches!(s.get_header(Fk::NULL), Err(StoreError::InvalidFk)));
    assert!(matches!(s.get_header(Fk(99)), Err(StoreError::NotFound)));
    // All-zero txid has no create head entry → NotFound (not InvalidFk).
    assert!(matches!(
        s.put_spend(&[0u8; 32], 0, Fk::NULL, 0),
        Err(StoreError::NotFound | StoreError::InvalidFk)
    ));
    drop(s);

    let file_path = td.path().join("notdir");
    std::fs::write(&file_path, b"x").unwrap();
    assert!(matches!(
        Store::create_tiny(&file_path),
        Err(StoreError::NotDirectory(_))
    ));

    let bad = td.path().join("badstore");
    std::fs::create_dir_all(&bad).unwrap();
    std::fs::write(bad.join("meta"), b"XXXX\x00\x00").unwrap();
    assert!(matches!(Store::open_tiny(&bad), Err(StoreError::BadMagic)));

    let bad2 = td.path().join("badschema");
    std::fs::create_dir_all(&bad2).unwrap();
    let mut meta = Vec::from(*b"RBT1");
    meta.extend_from_slice(&99u16.to_le_bytes());
    std::fs::write(bad2.join("meta"), meta).unwrap();
    assert!(matches!(
        Store::open_tiny(&bad2),
        Err(StoreError::BadSchema(99))
    ));

    let bad3 = td.path().join("shortmeta");
    std::fs::create_dir_all(&bad3).unwrap();
    std::fs::write(bad3.join("meta"), b"RB").unwrap();
    assert!(matches!(
        Store::open_tiny(&bad3),
        Err(StoreError::Corrupt(_))
    ));

    let parent_file = td.path().join("parent_is_file");
    std::fs::write(&parent_file, b"x").unwrap();
    assert!(Store::create_tiny(parent_file.join("store")).is_err());

    assert!(HeaderRecord::decode(&[0u8; 10]).is_err());
    assert!(TxRecord::decode(&[0u8; 10]).is_err());
}

#[test]
fn store_table_header_and_idx_corrupt() {
    use rbitcoin_primitives::{TableKind, SCHEMA_VERSION, STORE_MAGIC};
    let td = TestDatadir::new().unwrap();
    let store_dir = td.path().join("broken_kind");
    {
        let s = Store::create_tiny(&store_dir).unwrap();
        s.flush().unwrap();
    }
    let mut hb = std::fs::read(store_dir.join("header.body")).unwrap();
    hb[6..8].copy_from_slice(&TableKind::TxOut.as_u16().to_le_bytes());
    std::fs::write(store_dir.join("header.body"), &hb).unwrap();
    match Store::open_tiny(&store_dir) {
        Err(StoreError::BadKind { .. }) => {}
        Err(e) => panic!("expected BadKind, got {e}"),
        Ok(_) => panic!("expected BadKind"),
    }

    let store_dir2 = td.path().join("broken_magic");
    {
        Store::create_tiny(&store_dir2).unwrap().flush().unwrap();
    }
    let mut hb = std::fs::read(store_dir2.join("header.body")).unwrap();
    hb[0..4].copy_from_slice(b"XXXX");
    std::fs::write(store_dir2.join("header.body"), &hb).unwrap();
    match Store::open_tiny(&store_dir2) {
        Err(StoreError::BadMagic) => {}
        Err(e) => panic!("expected BadMagic, got {e}"),
        Ok(_) => panic!("expected BadMagic"),
    }

    let store_dir3 = td.path().join("broken_schema");
    {
        Store::create_tiny(&store_dir3).unwrap().flush().unwrap();
    }
    let mut hb = std::fs::read(store_dir3.join("header.body")).unwrap();
    hb[4..6].copy_from_slice(&123u16.to_le_bytes());
    std::fs::write(store_dir3.join("header.body"), &hb).unwrap();
    match Store::open_tiny(&store_dir3) {
        Err(StoreError::BadSchema(123)) => {}
        Err(e) => panic!("expected BadSchema, got {e}"),
        Ok(_) => panic!("expected BadSchema"),
    }

    let sd = td.path().join("empty_head");
    {
        Store::create_tiny(&sd).unwrap().flush().unwrap();
    }
    let head = sd.join("header.head");
    let mut bytes = std::fs::read(&head).unwrap();
    bytes[8..16].copy_from_slice(&16u64.to_le_bytes());
    bytes.truncate(16);
    std::fs::write(&head, bytes).unwrap();
    match Store::open_tiny(&sd) {
        Err(StoreError::Corrupt(_)) => {}
        Err(e) => panic!("expected Corrupt, got {e}"),
        Ok(_) => panic!("expected Corrupt"),
    }

    let sd2 = td.path().join("bad_slots");
    {
        Store::create_tiny(&sd2).unwrap().flush().unwrap();
    }
    let head = sd2.join("header.head");
    let mut bytes = std::fs::read(&head).unwrap();
    let logical = 16u64 + 40 * 3;
    bytes.resize(logical as usize, 0);
    bytes[8..16].copy_from_slice(&logical.to_le_bytes());
    std::fs::write(&head, bytes).unwrap();
    match Store::open_tiny(&sd2) {
        Err(StoreError::Corrupt(_)) => {}
        Err(e) => panic!("expected Corrupt, got {e}"),
        Ok(_) => panic!("expected Corrupt"),
    }

    let _ = (SCHEMA_VERSION, STORE_MAGIC);
}

// ─── Synthetic store growth (no PoW; tiny header.head rolls a generation) ───

fn poison_confirmed_merkle_root(store: &std::path::Path, fk: Fk, rec: &HeaderRecord) {
    let mut rec = rec.clone();
    rec.merkle_root = [0xee; 32];
    let enc = rec.encode();
    let path = store.join("header.body");
    let mut bytes = std::fs::read(&path).unwrap();
    let off = 16 + ((fk.0 - 1) as usize) * enc.len();
    bytes[off..off + enc.len()].copy_from_slice(&enc);
    std::fs::write(&path, bytes).unwrap();
}

fn pin_disconnect_to_genesis_reconnect_and_tip_shrink(
    q: Query,
    td: &TestDatadir,
    n: u32,
    saved: &[(HeaderRecord, rbitcoin_query::TxApply)],
) {
    let hashes: Vec<[u8; 32]> = saved.iter().map(|(h, _)| h.hash).collect();
    let top = n - 1;
    q.invalidate_height_by_hash_index();
    assert_eq!(q.process_owned_size_snapshot().h2h_keys, 0);
    let _ = q.confirm_stats().take_window();
    assert_eq!(q.height_of_hash(&hashes[0]).unwrap(), Some(Height(0)));
    let rebuilt = q.confirm_stats().take_window();
    assert_eq!(rebuilt.height_index_full_n, 1);
    assert_eq!(rebuilt.height_index_full_headers, u64::from(n));

    pin_disconnect_logs_and_rewinds_ibd_marks(&q, top, &hashes[top as usize]);
    assert!(q.height_of_hash(&hashes[top as usize]).unwrap().is_none());
    for _ in 1..top {
        q.disconnect_tip().unwrap();
    }
    assert_eq!(q.tip_height(), Some(Height(0)));
    assert!(q.height_of_hash(&hashes[1]).unwrap().is_none());
    assert_eq!(q.process_owned_size_snapshot().h2h_keys, 1);
    assert!(q
        .connect_block(
            Height(0),
            &HeaderRecord {
                prev_fk: Fk::NULL,
                version: 1,
                timestamp: 0,
                bits: 1,
                nonce: 0,
                merkle_root: [0; 32],
                hash: [1; 32],
                size: 0,
                weight: 0,
            },
            &[]
        )
        .is_err());

    pin_empty_chain_then_same_height_replace(&q, saved);
    assert_eq!(q.tip_height(), Some(Height(top)));
    assert_eq!(q.height_of_hash(&hashes[1]).unwrap(), Some(Height(1)));
    let (tip_fk, _) = q
        .get_header_by_hash(&hashes[top as usize])
        .unwrap()
        .unwrap();
    let tx_fks = q.block_tx_fks(Height(top)).unwrap();
    assert_eq!(
        q.confirm_blocks_run(&[rbitcoin_query::ConfirmPrepared {
            height: Height(top),
            header_fk: tip_fk,
            tx_fks,
        }])
        .unwrap(),
        [tip_fk],
        "re-confirming the tip is idempotent"
    );
    assert_eq!(
        q.headers_after_locator(&[], BlockHash::from_byte_array(hashes[2]), 5)
            .unwrap()
            .len(),
        1,
        "null locator + known stop is that one header"
    );
    assert!(q
        .headers_after_locator(&[], BlockHash::from_byte_array([0xee; 32]), 5)
        .unwrap()
        .is_empty());

    let poison_h = Height(n.saturating_sub(3));
    let (fk, rec) = q.header_at_height(poison_h).unwrap().unwrap();
    q.flush().unwrap();
    drop(q);
    poison_confirmed_merkle_root(&td.store_path(), fk, &rec);
    let q = Query::open_or_create_tiny(td.store_path()).unwrap();
    let tip = q
        .tip_height()
        .expect("open must keep a tip below the poison");
    assert!(
        tip.0 < n - 1,
        "VERIFY_TIP_BLOCKS=6 must shrink past poisoned merkle at {}: {tip:?}",
        poison_h.0
    );
    assert_eq!(
        tip,
        Height(n.saturating_sub(4)),
        "poison at n-3 shrinks to last good n-4"
    );
    pin_megakey_block_disconnect(&q, tip, hashes[tip.0 as usize]);
}

/// Disconnect genesis too, then rebuild from an empty chain with a
/// same-height replace at height 1 before the saved suffix.
fn pin_empty_chain_then_same_height_replace(
    q: &Query,
    saved: &[(HeaderRecord, rbitcoin_query::TxApply)],
) {
    let hashes: Vec<[u8; 32]> = saved.iter().map(|(h, _)| h.hash).collect();
    let n = saved.len() as u32;
    q.disconnect_tip().unwrap();
    assert!(q.tip_height().is_none());
    assert!(q.disconnect_tip().is_err(), "nothing left to disconnect");
    assert!(q.tip_header_fk().unwrap().is_none());
    assert!(q.height_of_hash(&hashes[0]).unwrap().is_none());
    assert_eq!(q.process_owned_size_snapshot().h2h_keys, 0);
    assert!(q.pin_chain_view().unwrap().is_none());
    assert_eq!(q.sh_lag_heights(), 0);
    assert_eq!(q.locator_hashes().unwrap().len(), 1);
    assert!(q
        .headers_after_locator(&[], BlockHash::from_byte_array([0; 32]), 5)
        .unwrap()
        .is_empty());

    let (g, g_ta) = &saved[0];
    let g_fk = q
        .connect_block(Height(0), g, std::slice::from_ref(g_ta))
        .unwrap();
    let (mut alt, alt_ta) = saved[1].clone();
    alt.nonce += 7;
    alt.hash = rbitcoin_store::block_header_hash(
        alt.version,
        &hashes[0],
        &alt.merkle_root,
        alt.timestamp,
        alt.bits,
        alt.nonce,
    );
    alt.prev_fk = g_fk;
    q.connect_block(Height(1), &alt, std::slice::from_ref(&alt_ta))
        .unwrap();
    assert_eq!(q.height_of_hash(&alt.hash).unwrap(), Some(Height(1)));
    assert!(q.height_of_hash(&hashes[1]).unwrap().is_none());
    q.disconnect_tip().unwrap();
    assert!(
        q.height_of_hash(&alt.hash).unwrap().is_none(),
        "same-height replace drops the old hash"
    );
    for h in 1..n {
        let (header, ta) = &saved[h as usize];
        q.connect_block(Height(h), header, std::slice::from_ref(ta))
            .unwrap();
    }
}

fn pin_disconnect_logs_and_rewinds_ibd_marks(q: &Query, top: u32, top_hash: &[u8; 32]) {
    let loc_fk = q.block_tx_fks(Height(top)).unwrap()[0];
    q.set_lookup_taken_hi(Some(top + 4));
    q.set_lookup_started_hi(Some(top + 4));
    q.set_class_a_hi(Some(top + 2));
    let pair = rbitcoin_store::CreateLocPair {
        txout: (10, 8),
        spent: (20, 8),
        n_out: 1,
    };
    q.note_write_create_loc(&[loc_fk], &[pair], top);
    assert!(q.write_create_loc(loc_fk).is_some());

    rbitcoin_log::capture_logs(true);
    q.disconnect_tip().unwrap();
    let logs = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    let line = format!(
        "DisconnectTip: hash={} height={top} tx=1",
        BlockHash::from_byte_array(*top_hash)
    );
    assert!(
        logs.iter()
            .any(|(l, m)| *l == rbitcoin_log::Level::Warn && m.contains(&line)),
        "{logs:?}"
    );
    assert_eq!(q.lookup_taken_hi(), Some(top - 1));
    assert_eq!(q.lookup_started_hi(), Some(top - 1));
    assert_eq!(q.class_a_hi(), Some(top - 1));
    assert!(
        q.write_create_loc(loc_fk).is_none(),
        "disconnect drops write loc packs at or above that height"
    );
}

/// 257 creates of one script in one block make its scripthash head an
/// extent. Disconnecting that block unlinks every create and truncates the
/// tweak index with it.
fn pin_megakey_block_disconnect(q: &Query, tip: Height, tip_hash: [u8; 32]) {
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{script_hash, InputRecord, OutputRecord, ShHeadValue};

    let h = tip.0 + 1;
    q.set_sptweaks_enabled(true, Height(0)).unwrap();
    let next = q.sptweaks_next_height().unwrap().0;
    let catch_up: Vec<_> = (next..h)
        .map(|at| {
            let fk = q.header_at_height(Height(at)).unwrap().unwrap().0;
            (Height(at), fk, vec![None])
        })
        .collect();
    q.put_sp_tweaks_blocks(&catch_up).unwrap();
    assert_eq!(q.sptweaks_next_height(), Some(Height(h)));
    let hot = vec![0x99u8];
    let txs: Vec<TxApply> = (0..257u32)
        .map(|i| {
            let mut txid = [0x3c; 32];
            txid[0..4].copy_from_slice(&h.to_le_bytes());
            txid[4..8].copy_from_slice(&i.to_le_bytes());
            TxApply {
                tx: TxRecord {
                    txid,
                    version: 1,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 1,
                    output_start_fk: Fk::NULL,
                    output_count: 1,
                },
                inputs: vec![InputRecord {
                    prev_txid: [0u8; 32],
                    create_fk: Fk::NULL,
                    prev_index: u32::MAX,
                    sequence: u32::MAX,
                    script_sig: vec![i as u8, (i >> 8) as u8],
                    witness: vec![],
                }],
                outputs: vec![OutputRecord::unspent(1, hot.clone())],
            }
        })
        .collect();
    let merkle = [0x3d; 32];
    let header = HeaderRecord {
        prev_fk: q.tip_header_fk().unwrap().unwrap(),
        version: 1,
        timestamp: h,
        bits: 1,
        nonce: 7,
        merkle_root: merkle,
        hash: rbitcoin_store::block_header_hash(1, &tip_hash, &merkle, h, 1, 7),
        size: 0,
        weight: 0,
    };
    let fk = q.connect_block(Height(h), &header, &txs).unwrap();
    q.put_sp_tweaks_block(Height(h), fk, &vec![None; txs.len()])
        .unwrap();
    assert_eq!(q.sptweaks_next_height(), Some(Height(h + 1)));
    let sh = script_hash(&hot);
    match q.store().scripthash.head_value(&sh).unwrap().unwrap() {
        ShHeadValue::Extent { .. } => {}
        other => panic!("expected extent megakey after 257 creates, got {other:?}"),
    }
    assert_eq!(q.scripthash_history(&sh).unwrap().len(), 257);

    q.disconnect_tip().unwrap();
    assert_eq!(q.tip_height(), Some(tip));
    assert!(
        q.scripthash_history(&sh).unwrap().is_empty(),
        "disconnected megakey creates must not remain in SH"
    );
    assert_eq!(q.sptweaks_next_height(), Some(Height(h)));
    assert!(q.load_thin_tweaks(Height(h)).unwrap().is_none());
}

fn copy_flat_dir(from: &std::path::Path, to: &std::path::Path) {
    let _ = std::fs::remove_dir_all(to);
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
    }
}

/// Tweak-index crash states, each followed by a reopen: a disconnect whose
/// `confirmed[]` shrink reached disk before its tweak truncate did (restored
/// snapshot), then a put whose body bytes reached disk without their idx slot.
/// Reopen trims tweaks to the tip and the last record to its `n_tx`.
fn pin_sp_tweaks_survive_crashes(
    q: Query,
    td: &TestDatadir,
    n: u32,
    saved: &[(HeaderRecord, rbitcoin_query::TxApply)],
) -> Query {
    let store = td.store_path();
    q.set_sptweaks_enabled(true, Height(0)).unwrap();
    let items: Vec<_> = (0..n)
        .map(|h| {
            let fk = q.header_at_height(Height(h)).unwrap().unwrap().0;
            (Height(h), fk, vec![None])
        })
        .collect();
    q.put_sp_tweaks_blocks(&items).unwrap();
    assert_eq!(q.sptweaks_next_height(), Some(Height(n)));
    let snap = td.path().join("sptweaks-snap");
    for d in ["sp_tweaks.idx", "sp_tweaks.body"] {
        copy_flat_dir(&store.join(d), &snap.join(d));
    }
    q.disconnect_tip().unwrap();
    q.flush().unwrap();
    drop(q);
    for d in ["sp_tweaks.idx", "sp_tweaks.body"] {
        copy_flat_dir(&snap.join(d), &store.join(d));
    }

    let q = Query::open_or_create_tiny(&store).unwrap();
    assert_eq!(q.tip_height(), Some(Height(n - 2)));
    q.set_sptweaks_enabled(true, Height(0)).unwrap();
    assert_eq!(
        q.sptweaks_next_height(),
        Some(Height(n - 1)),
        "open drops tweaks above the tip"
    );
    let (header, ta) = &saved[(n - 1) as usize];
    let fk = q
        .connect_block(Height(n - 1), header, std::slice::from_ref(ta))
        .unwrap();
    q.put_sp_tweaks_blocks(&[(Height(n - 1), fk, vec![None])])
        .unwrap();
    q.flush().unwrap();
    drop(q);

    let body = store.join("sp_tweaks.body").join("000000");
    let mut raw = std::fs::read(&body).unwrap();
    let hwm = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    raw.truncate(hwm as usize);
    raw.push(0);
    raw[8..16].copy_from_slice(&(hwm + 1).to_le_bytes());
    std::fs::write(&body, &raw).unwrap();

    let q = Query::open_or_create_tiny(&store).unwrap();
    q.set_sptweaks_enabled(true, Height(0)).unwrap();
    assert!(
        q.load_thin_tweaks(Height(n - 1)).unwrap().is_some(),
        "last record reads without the orphan byte"
    );
    q
}

#[test]
fn chain_connect_reorg_and_growth() {
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{InputRecord, OutputRecord};

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create_tiny(td.store_path()).unwrap();

    // Default hash head is 64 slots; 80 blocks (header keys) force header.head.g1.
    // Merkle root must match the Class A txid(s) so tip-window revalidate on reopen
    // (VERIFY_TIP_BLOCKS) does not false-positive shrink the tip.
    const N: u32 = 80;
    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    let mut saved = Vec::with_capacity(N as usize);
    for h in 0..N {
        let version = 1;
        let timestamp = h;
        let bits = 1;
        let nonce = h;
        let mut txid = [0u8; 32];
        txid[0..4].copy_from_slice(&h.to_le_bytes());
        txid[31] = 0xcb;
        // Single-tx "block": merkle root == coinbase txid (internal byte order).
        let merkle = txid;
        let ph = parent_hash.unwrap_or([0u8; 32]);
        let hash = rbitcoin_store::block_header_hash(version, &ph, &merkle, timestamp, bits, nonce);
        let header = HeaderRecord {
            prev_fk: prev,
            version,
            timestamp,
            bits,
            nonce,
            merkle_root: merkle,
            hash,
            size: 0,
            weight: 0,
        };
        let ta = TxApply {
            tx: TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk::NULL,
                prev_index: u32::MAX,
                sequence: u32::MAX,
                script_sig: vec![0],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
        };
        parent_hash = Some(header.hash);
        saved.push((header.clone(), ta.clone()));
        prev = q
            .connect_block(Height(h), &header, std::slice::from_ref(&ta))
            .unwrap();
    }
    assert_eq!(q.tip_height(), Some(Height(N - 1)));
    q.flush().unwrap();
    drop(q);

    let q = Query::open_or_create_tiny(td.store_path()).unwrap();
    assert_eq!(q.tip_height(), Some(Height(N - 1)));
    let q = pin_sp_tweaks_survive_crashes(q, &td, N, &saved);
    pin_disconnect_to_genesis_reconnect_and_tip_shrink(q, &td, N, &saved);
}

/// Simulate kill -9 mid Class C: `strong_tx` written for tip+1 but
/// `confirmed[]` not advanced. Class A does not write spend point edges
/// (confirm `post_commit` annotates after tip). Re-confirm must not
/// false-positive PrevoutSpent (tip is the Class C commit point).
#[test]
fn confirm_survives_partial_class_c_without_tip_advance() {
    use rbitcoin_consensus::{
        accept_and_connect_block, commit_class_a_block, confirm_wire_run, ChainParams, Milestone,
    };
    use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis, spend_anyone_can_spend};

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create_tiny(td.store_path()).unwrap();
    q.set_spend_index(true);
    q.set_tx_index(true);
    let ms = Milestone::NONE;
    let params = ChainParams::regtest();
    let maturity = params.coinbase_maturity();

    let genesis = regtest_genesis();
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;

    let b1 = mine_regtest_block(tip, tip_time + 600, 1, vec![]);
    let cb1 = b1.txdata[0].compute_txid();
    accept_and_connect_block(&q, &params, Height(1), &b1, ms).unwrap();
    tip = b1.block_hash();
    tip_time = b1.header.time;

    let last_pad = maturity + 1;
    for h in 2..=last_pad {
        let b = mine_regtest_block(tip, tip_time + 600, h, vec![]);
        accept_and_connect_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
    }
    let tip_before = q.tip_height().unwrap();
    assert_eq!(tip_before, Height(last_pad));

    let spend_h = last_pad + 1;
    let spend = spend_anyone_can_spend(cb1, 0, Amount::from_sat(49_0000_0000));
    let b_spend = mine_regtest_block(tip, tip_time + 600, spend_h, vec![spend]);
    commit_class_a_block(&q, &params, Height(spend_h), &b_spend, ms).unwrap();

    let hash = b_spend.block_hash().to_byte_array();
    let (header_fk, _) = q.get_header_by_hash(&hash).unwrap().unwrap();
    let tx_fks = q.store().header_txs.get_list(header_fk).unwrap().unwrap();
    assert!(tx_fks.len() >= 2, "coinbase + spend");

    let first = tx_fks[0];
    q.store()
        .strong_tx
        .set_strong_range(first, tx_fks.len() as u32, header_fk)
        .unwrap();
    assert_eq!(q.tip_height(), Some(tip_before));
    assert!(
        q.store().strong_tx.is_strong(tx_fks[1]).unwrap(),
        "sim: spending tx marked strong without tip"
    );
    assert!(
        q.spenders_raw(cb1.as_byte_array(), 0).unwrap().is_empty(),
        "Class A does not write spend point edges"
    );
    // Best-chain spenders must ignore strong-above-tip.
    assert!(
        q.spenders(cb1.as_byte_array(), 0).unwrap().is_empty(),
        "spenders must not see uncommitted Class C"
    );
    assert!(
        !q.store().is_confirmed_strong(tx_fks[1]).unwrap(),
        "is_confirmed_strong false while height > tip"
    );

    // Re-confirm tip+1 (restart after kill -9) must succeed.
    confirm_wire_run(&q, &params, ms, &[(Height(spend_h), b_spend.clone())])
        .expect("re-confirm after partial Class C (kill -9 class)");
    assert_eq!(q.tip_height(), Some(Height(spend_h)));
    assert_eq!(
        q.spenders(cb1.as_byte_array(), 0).unwrap().len(),
        1,
        "after tip commit the spend is confirmed-strong"
    );

    // Open-time repair: leave another partial Class C and reopen.
    let b_next = mine_regtest_block(
        b_spend.block_hash(),
        b_spend.header.time + 600,
        spend_h + 1,
        vec![],
    );
    commit_class_a_block(&q, &params, Height(spend_h + 1), &b_next, ms).unwrap();
    let hash2 = b_next.block_hash().to_byte_array();
    let (hfk2, _) = q.get_header_by_hash(&hash2).unwrap().unwrap();
    let fks2 = q.store().header_txs.get_list(hfk2).unwrap().unwrap();
    q.store()
        .strong_tx
        .set_strong_range(fks2[0], fks2.len() as u32, hfk2)
        .unwrap();
    q.flush().unwrap();
    drop(q);

    let q2 = Query::open_or_create_tiny(td.store_path()).unwrap();
    assert!(
        !q2.store().strong_tx.is_strong(fks2[0]).unwrap(),
        "open must repair strong bits above tip"
    );
    confirm_wire_run(&q2, &params, ms, &[(Height(spend_h + 1), b_next)])
        .expect("confirm after open repair");
    assert_eq!(q2.tip_height(), Some(Height(spend_h + 1)));
}

/// Leftover identity: durable TipOnly is the one connected fk; RAM leftover
/// maps keep one fk per txid (last write clobbers).
fn pin_leftover_tiponly_one_fk(q: &Query, cb1: bitcoin::Txid, create_fk: Fk) {
    let tid = *cb1.as_byte_array();
    let tip = q
        .tx_fk_by_txid_tip(&tid)
        .unwrap()
        .expect("TipOnly connected instance");
    let any = q.tx_fk_by_txid(&tid).unwrap().expect("txid head identity");
    assert_eq!(tip, create_fk);
    assert_eq!(any, tip, "one fk per txid on leftover head");
    let stamp =
        stamp_external_parents(q.store(), &[tid], &InFlight::new(), None, q.confirm_stats())
            .expect("plan=None leftover TipOnly stamp");
    assert_eq!(stamp.resolved.get(&tid), Some(&tip));
    let mut inflight = InFlight::new();
    inflight.note_creates([(tid, tip)], Some(1));
    let (_, _, once) = inflight.size_snapshot();
    let later = Fk(tip.0.saturating_add(1));
    inflight.note_creates([(tid, later)], Some(2));
    let (_, _, twice) = inflight.size_snapshot();
    assert_eq!(twice, once, "creates map stays one slot on clobber");
    assert_eq!(inflight.get_create_fk(&tid), Some(later));
}

fn spend_edge_of(plan: &rbitcoin_query::ArchiveWritePlan) -> rbitcoin_query::SpendEdge {
    *plan
        .edges
        .values()
        .flatten()
        .find(|e| e.vout != u32::MAX)
        .expect("spend edge")
}

/// Before the spend is archived, its connected parent resolves by TipOnly
/// head: through the leftover probe with no wave, and through every BQ wave
/// that carries it (a wave skeleton needs no leftover probe).
fn pin_head_parent_via_waves_and_leftover_stamp(
    q: &Query,
    params: &ChainParams,
    ms: Milestone,
    cb1: bitcoin::Txid,
    b_spend: &Block,
    spend_h: u32,
) {
    use bitcoin::consensus::encode::serialize;
    use rbitcoin_consensus::{
        confirm_bq_resolve_wave_capped, confirm_wire_lookup_stamp, take_wave_items_for_load,
        WireLoadPipeline, BQ_RESOLVE_WAVE_MAX_BLOCKS, BQ_RESOLVE_WAVE_MAX_INPUTS,
    };
    use rbitcoin_test::mine::spend_anyone_can_spend;

    let parent = cb1.to_byte_array();
    let head_fk = q.tx_fk_by_txid_tip(&parent).unwrap().expect("connected");
    let items = [(Height(spend_h), std::sync::Arc::new(b_spend.clone()), None)];
    let stamped = confirm_wire_lookup_stamp(q, params, ms, &items, None)
        .expect("a leftover connected parent TipOnly-heads");
    let edge = spend_edge_of(&stamped.plan.expect("a new body needs a plan"));
    assert_eq!((edge.prev_txid, edge.create_fk), (parent, head_fk));
    let leftover = q.confirm_stats().last_plan_batch();
    assert!(
        leftover.head_need >= 1 && leftover.head_hit == leftover.head_need,
        "{leftover:?}"
    );

    let rival = mine_regtest_block(
        b_spend.block_hash(),
        b_spend.header.time + 600,
        spend_h + 1,
        vec![spend_anyone_can_spend(
            cb1,
            0,
            Amount::from_sat(48_0000_0000),
        )],
    );
    for (h, b) in [(spend_h, b_spend), (spend_h + 1, &rival)] {
        q.block_queue_enqueue(
            h,
            b.block_hash().to_byte_array(),
            u64::from(h),
            &serialize(b),
        )
        .unwrap();
    }
    let wave = |h: u32| {
        confirm_bq_resolve_wave_capped(
            q,
            params,
            ms,
            &[h],
            BQ_RESOLVE_WAVE_MAX_BLOCKS,
            BQ_RESOLVE_WAVE_MAX_INPUTS,
        )
        .unwrap()
    };
    let w1 = wave(spend_h);
    assert!(w1.stats.hits >= 1);
    assert!(w1.parent_ids.get(&parent).is_some());
    let ext = stamp_external_parents(
        q.store(),
        &[parent],
        &InFlight::new(),
        Some(&w1.parent_ids),
        q.confirm_stats(),
    )
    .unwrap();
    assert_eq!(
        ext.head_need_n, 0,
        "a wave skeleton needs no leftover probe"
    );
    let inflight = InFlight::new();
    let pipe = WireLoadPipeline {
        path_lo: spend_h,
        parent_hash: None,
        next_tx_start: q.tx_body_count().saturating_add(1),
        in_flight: &inflight,
        skeleton: Some(w1.parent_ids.clone()),
        carried_need: w1
            .items
            .iter()
            .flat_map(|(_, _, w)| w.spend_keys.iter().map(|&(t, _)| t))
            .collect(),
        carried_header_fks: Vec::new(),
        carried_header_hashes: Vec::new(),
    };
    let stamped = confirm_wire_lookup_stamp(q, params, ms, &items, Some(&pipe)).unwrap();
    let edge = spend_edge_of(&stamped.plan.expect("a new body needs a plan"));
    assert_eq!(edge.create_fk, head_fk);
    assert!(take_wave_items_for_load(q, &w1.items, q.lookup_taken_gen()).unwrap());

    let w2 = wave(spend_h + 1);
    assert!(
        w2.stats.keys >= 1 && w2.stats.hits >= 1,
        "a second wave TipOnlys the same connected parent again"
    );
    assert!(w2.parent_ids.get(&parent).is_some());
    assert!(take_wave_items_for_load(q, &w2.items, q.lookup_taken_gen()).unwrap());
    assert!(!q.block_queue_has_height(spend_h));
    assert!(!q.block_queue_has_height(spend_h + 1));
}

/// Once the spend is in Class A, lookup stamps it without a plan: the
/// archived create pairs are the block's txids and fks. A header whose tx
/// list no longer matches the wire block refuses as Corrupt.
fn pin_plan_none_stamp_of_archived_spend(
    q: &Query,
    params: &ChainParams,
    ms: Milestone,
    b_spend: &Block,
    spend_h: u32,
) {
    use rbitcoin_consensus::{confirm_wire_lookup_stamp, ConsensusError};

    let hash = b_spend.block_hash().to_byte_array();
    let (hfk, _) = q.get_header_by_hash(&hash).unwrap().unwrap();
    let fks = q.header_tx_fks(hfk, Some(&hash)).unwrap().unwrap();
    let items = [(Height(spend_h), std::sync::Arc::new(b_spend.clone()), None)];
    let before = q.confirm_stats().last_plan_batch();
    let stamped = confirm_wire_lookup_stamp(q, params, ms, &items, None).expect("archived stamp");
    assert!(stamped.plan.is_none(), "already archived: plan=None");
    let pairs: Vec<_> = b_spend
        .txdata
        .iter()
        .map(|t| t.compute_txid().to_byte_array())
        .zip(fks.iter().copied())
        .collect();
    assert_eq!(stamped.archived_create_pairs(), pairs);
    assert_eq!(stamped.last_height_hash(), Some((spend_h, hash)));
    let after = q.confirm_stats().last_plan_batch();
    assert_eq!(
        (after.head_need, after.head_hit),
        (before.head_need, before.head_hit),
        "a stamp-only note keeps the last leftover counts"
    );

    let n = fks.len() as u32;
    q.store().header_txs.put_range(hfk, fks[0], n + 1).unwrap();
    match confirm_wire_lookup_stamp(q, params, ms, &items, None) {
        Err(ConsensusError::Store(StoreError::Corrupt(m))) => {
            assert_eq!(m, "invariant: archived stamp tx_fks/txids length");
        }
        Err(e) => panic!("list/wire length mismatch must be Corrupt, got {e}"),
        Ok(_) => panic!("list/wire length mismatch must fail the stamp"),
    }
    q.store().header_txs.put_range(hfk, fks[0], n).unwrap();
}

/// Resume: spend archived with create_fk (archive sticky/head); confirm spends.
#[test]
fn resume_tx_head_resolves_external_prev() {
    use rbitcoin_consensus::{
        accept_and_connect_block, commit_class_a_block, confirm_wire_run, ChainParams, Milestone,
    };
    use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis, spend_anyone_can_spend};

    let td = TestDatadir::new().unwrap();
    let ms = Milestone::height(1_000_000);
    let params = ChainParams::regtest();
    let maturity = params.coinbase_maturity();

    // Session 1: mine + confirm pad so coinbase is mature; leave spend unarchived.
    let (cb1, tip, tip_time, spend_h, b_spend) = {
        let q = Query::open_or_create_tiny(td.store_path()).unwrap();
        q.enter_direct_index_mode().unwrap();
        let genesis = regtest_genesis();
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
        let mut tip = genesis.block_hash();
        let mut tip_time = genesis.header.time;
        let b1 = mine_regtest_block(tip, tip_time + 600, 1, vec![]);
        let cb1 = b1.txdata[0].compute_txid();
        accept_and_connect_block(&q, &params, Height(1), &b1, ms).unwrap();
        tip = b1.block_hash();
        tip_time = b1.header.time;
        let last_pad = maturity + 1;
        for h in 2..=last_pad {
            let b = mine_regtest_block(tip, tip_time + 600, h, vec![]);
            accept_and_connect_block(&q, &params, Height(h), &b, ms).unwrap();
            tip = b.block_hash();
            tip_time = b.header.time;
        }
        let spend_h = last_pad + 1;
        let spend = spend_anyone_can_spend(cb1, 0, Amount::from_sat(49_0000_0000));
        let b_spend = mine_regtest_block(tip, tip_time + 600, spend_h, vec![spend]);
        q.flush().unwrap();
        (cb1, tip, tip_time, spend_h, b_spend)
    };
    let _ = (tip, tip_time);

    // Session 2: reopen, archive spend (create_fk via head), confirm.
    {
        let q = Query::open_or_create_tiny(td.store_path()).unwrap();
        q.enter_direct_index_mode().unwrap();
        assert!(
            q.tx_fk_by_txid(cb1.as_byte_array()).unwrap().is_some(),
            "tx.head must retain mature coinbase create_fk across reopen"
        );
        pin_head_parent_via_waves_and_leftover_stamp(&q, &params, ms, cb1, &b_spend, spend_h);
        commit_class_a_block(&q, &params, Height(spend_h), &b_spend, ms).unwrap();
        pin_plan_none_stamp_of_archived_spend(&q, &params, ms, &b_spend, spend_h);
        let fks = q
            .store()
            .header_txs
            .get_list(
                q.get_header_by_hash(&b_spend.block_hash().to_byte_array())
                    .unwrap()
                    .unwrap()
                    .0,
            )
            .unwrap()
            .unwrap();
        let rec = q.get_tx(fks[1]).unwrap();
        let inp = q.tx_input_at_fk(fks[1], &rec, 0).unwrap();
        assert!(
            !inp.create_fk.is_null(),
            "v10 Class A stores create_fk (not prev_txid on disk)"
        );
        assert_eq!(
            q.resolve_prev_txid(&inp).unwrap(),
            *cb1.as_byte_array(),
            "create body supplies parent txid for wire"
        );

        confirm_wire_run(&q, &params, ms, &[(Height(spend_h), b_spend)])
            .expect("create_fk spend confirms");
        assert_eq!(q.tip_height(), Some(Height(spend_h)));
        assert!(
            q.is_outpoint_spent(cb1.as_byte_array(), 0).unwrap(),
            "durable spend must see the confirmed spend"
        );
        assert_eq!(
            q.spenders(cb1.as_byte_array(), 0).unwrap().len(),
            1,
            "Direct confirm writes durable spend annotations"
        );
        pin_leftover_tiponly_one_fk(&q, cb1, inp.create_fk);
    }
}

// ─── Consensus + reconstruct: one mature mine, many assertions ──────────────

/// Single mature-chain pad covers consensus + scripthash + reconstruct + reorg:
/// - accept genesis + maturity pad + spend + double-spend reject
/// - create_fk on spend + reconstruct
/// - reconstruct after reopen (sampled heights)
/// - scripthash history / balance / listunspent for OP_TRUE
/// - disconnect tip restores spent coinbase UTXO
/// - locator/headers + service flags
#[allow(clippy::cognitive_complexity)] // one fixture, many confirm/SH arms
#[test]
fn consensus_mature_chain_spend_reconstruct_and_scripthash() {
    use bitcoin::p2p::ServiceFlags;
    use rbitcoin_consensus::{commit_class_a_block, confirm_wire_run};
    use rbitcoin_net::local_service_flags;
    use rbitcoin_store::script_hash;

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create_tiny(td.store_path()).unwrap();
    let params = ChainParams::regtest();

    // ONE maturity pad for spend, reconstruct, and scripthash contracts.
    let chain = build_mature_regtest_with_spend(&q, &params);
    let tip_h = chain.tip_height();
    assert_eq!(q.tip_height(), Some(Height(tip_h)));
    assert_eq!(chain.tip_hash(), chain.blocks.last().unwrap().block_hash());
    assert!(tip_h >= params.coinbase_maturity() + 2);

    // Spend of height-1 coinbase succeeded at tip.
    assert_eq!(
        q.spenders(chain.matured_coinbase_txid.as_byte_array(), 0)
            .unwrap()
            .len(),
        1
    );
    let spend_block = &chain.blocks[chain.spend_height as usize];
    assert!(
        spend_block.txdata.len() >= 2,
        "spend block should be multi-tx"
    );

    // External prev_txid on Class A + reconstruct.
    let spend_txid = spend_block.txdata[1].compute_txid().to_byte_array();
    let (_spend_fk, rec) = q
        .get_tx_by_txid(&spend_txid)
        .unwrap()
        .expect("spend indexed");
    let inp = q.tx_input(&rec, 0).unwrap();
    assert_eq!(
        q.resolve_prev_txid(&inp).unwrap(),
        chain.matured_coinbase_txid.to_byte_array()
    );
    assert!(
        !inp.create_fk.is_null(),
        "v10 spend input must carry create_fk"
    );
    assert_reconstruct_eq(&q, chain.spend_height, spend_block);
    let cbin = q
        .tx_input(
            &q.get_tx(q.block_tx_fks(Height(chain.spend_height)).unwrap()[0])
                .unwrap(),
            0,
        )
        .unwrap();
    assert!(cbin.is_coinbase());

    // Scripthash index on OP_TRUE coinbases / spend (same pad — no second mine).
    let sh = script_hash(&[0x51]);
    let history = q.scripthash_history(&sh).unwrap();
    assert!(
        !history.is_empty() && history.len() >= 2,
        "OP_TRUE history empty or short: {}",
        history.len()
    );
    let bal = q.scripthash_balance(&sh).unwrap();
    assert!(bal.confirmed > 0, "confirmed={}", bal.confirmed);
    assert_eq!(bal.unconfirmed, 0);
    let utxos = q.scripthash_listunspent(&sh).unwrap();
    assert!(!utxos.is_empty());
    assert!(!utxos
        .iter()
        .any(|u| u.tx_hash == chain.matured_coinbase_txid.to_byte_array() && u.tx_pos == 0));
    let mut sh_slot = None;
    pin_scripthash_views_on_pad(&q, &chain, &mut sh_slot);
    pin_block_and_tx_surface_on_pad(&q, &chain);

    // Extra store/query surface on the same pad (coverage without a second open).
    assert!(q.scripthash_entry_count() > 0);
    let tip_fk = q.tip_header_fk().unwrap().expect("tip header fk");
    let tip_hdr = q.get_header(tip_fk).unwrap();
    assert_eq!(BlockHash::from_byte_array(tip_hdr.hash), chain.tip_hash());
    let by_hash = q
        .get_header_by_hash(&chain.tip_hash().to_byte_array())
        .unwrap();
    assert!(by_hash.is_some());
    let at_h = q.header_at_height(Height(tip_h)).unwrap();
    assert!(at_h.is_some());
    let fks = q.block_tx_fks(Height(1)).unwrap();
    assert_eq!(fks.len(), 1);
    let cb1 = q.get_tx(fks[0]).unwrap();
    assert_eq!(cb1.txid, chain.matured_coinbase_txid.to_byte_array());
    let out0 = q.tx_output(&cb1, 0).unwrap();
    // Coinbase output script is OP_TRUE anyone-can-spend in our miner.
    assert_eq!(out0.script.as_slice(), &[0x51]);
    let full = q.store().get_tx_full(fks[0]).unwrap();
    assert_eq!(full.0.txid, cb1.txid);
    assert!(q.store().is_confirmed_strong(fks[0]).unwrap());
    // Body/head occupancy counters (store stats used by RPC/status).
    assert!(q.tx_body_count() > 0);
    assert!(q.tx_head_occupied() > 0);
    // Spentness of the matured coinbase out (spent at tip).
    assert!(q
        .is_outpoint_spent(chain.matured_coinbase_txid.as_byte_array(), 0)
        .unwrap());
    assert_eq!(
        q.height_of_hash(&chain.tip_hash().to_byte_array()).unwrap(),
        Some(Height(tip_h))
    );
    // tip-1 fast path in height_of_hash
    if tip_h > 0 {
        assert_eq!(
            q.height_of_hash(
                &chain.blocks[(tip_h - 1) as usize]
                    .block_hash()
                    .to_byte_array()
            )
            .unwrap(),
            Some(Height(tip_h - 1))
        );
    }
    assert_eq!(
        q.height_of_hash(&chain.blocks[1].block_hash().to_byte_array())
            .unwrap(),
        Some(Height(1))
    );
    // Mid-chain height (exercises reverse walk, not only tip/tip-1 fast path).
    let mid = tip_h / 2;
    assert_eq!(
        q.height_of_hash(&chain.blocks[mid as usize].block_hash().to_byte_array())
            .unwrap(),
        Some(Height(mid))
    );
    assert!(q.height_of_hash(&[0xcd; 32]).unwrap().is_none());
    let wh = q.wire_header_at_height(Height(tip_h)).unwrap();
    assert_eq!(wh.block_hash(), chain.tip_hash());
    let wh0 = q.wire_header_at_height(Height::GENESIS).unwrap();
    assert_eq!(wh0.block_hash(), chain.blocks[0].block_hash());

    // Double-spend must fail (tip still includes original spend).
    let tip_block = chain.blocks.last().unwrap();
    let spend2 = spend_anyone_can_spend(
        chain.matured_coinbase_txid,
        0,
        Amount::from_sat(48_0000_0000),
    );
    let b_bad = mine_regtest_block(
        tip_block.block_hash(),
        tip_block.header.time + 600,
        tip_h + 1,
        vec![spend2],
    );
    let err = accept_and_connect_block(&q, &params, Height(tip_h + 1), &b_bad, Milestone::NONE);
    let msg = format!("{err:?}");
    assert!(
        err.is_err()
            && (msg.contains("PrevoutSpent")
                || msg.contains("BadTx")
                || msg.contains("spent")
                || msg.contains("multi-spender")
                || msg.contains("double")),
        "double-spend must reject, got {err:?}"
    );
    assert_eq!(q.tip_height(), Some(Height(tip_h)));

    commit_class_a_block(&q, &params, Height(tip_h + 1), &b_bad, Milestone::NONE).unwrap();
    let err = accept_and_connect_block(&q, &params, Height(tip_h + 1), &b_bad, Milestone::NONE)
        .expect_err("Class A then accept double-spend must fail structural");
    let msg = err.to_string();
    assert!(
        msg.contains("spent") || msg.contains("PrevoutSpent") || msg.contains("prevout"),
        "unexpected reject: {msg}"
    );
    let wire_err = confirm_wire_run(
        &q,
        &params,
        Milestone::NONE,
        &[(Height(tip_h + 1), b_bad.clone())],
    )
    .expect_err("wire-path double-spend must fail");
    let wire_msg = format!("{wire_err}").to_lowercase();
    assert!(
        wire_msg.contains("spent") || wire_msg.contains("double") || wire_msg.contains("bad"),
        "wire double-spend: {wire_err}"
    );
    assert_eq!(q.tip_height(), Some(Height(tip_h)));
    pin_archived_sibling_bodies(&q, &params, &chain, &b_bad);

    // Reorg: disconnect tip (spend) → matured coinbase UTXO returns.
    q.disconnect_tip().unwrap();
    assert_eq!(q.tip_height(), Some(Height(tip_h - 1)));
    let utxos2 = q.scripthash_listunspent(&sh).unwrap();
    assert!(
        utxos2
            .iter()
            .any(|u| u.tx_hash == chain.matured_coinbase_txid.to_byte_array() && u.tx_pos == 0),
        "after disconnect, matured coinbase should be unspent again"
    );
    let slot_utxos = q.scripthash_listunspent_slot(&sh, &mut sh_slot).unwrap();
    assert_eq!(
        slot_utxos, utxos2,
        "a tip change must not serve the join slot pinned before it"
    );
    pin_abandoned_fork_is_not_a_parent(&q, &params, &chain);

    // Snapshot SH creates before reopen (kill mid-Class-C shape).
    use rbitcoin_store::ScriptHashRecord;
    use std::collections::HashMap;
    let n0 = q.scripthash_entry_count();
    let mut durable: Vec<ScriptHashRecord> = Vec::new();
    q.store()
        .scripthash
        .for_each_live_create(|create_tx_fk| {
            durable.push(ScriptHashRecord::from_fk([0u8; 32], create_tx_fk));
        })
        .unwrap();
    assert_eq!(durable.len() as u64, n0);

    q.flush().unwrap();
    drop(q);

    // Reopen — reconstruct without RAM cache; durable SH must not duplicate.
    let q = Query::open_or_create_tiny(td.store_path()).unwrap();
    assert_eq!(q.tip_height(), Some(Height(tip_h - 1)));
    let mut indexed = std::collections::HashSet::new();
    q.store()
        .scripthash
        .for_each_live_create(|c| {
            indexed.insert(c.0);
        })
        .unwrap();
    let to_put: Vec<_> = durable
        .into_iter()
        .filter(|r| !indexed.contains(&r.create_tx_fk.0))
        .collect();
    assert!(
        to_put.is_empty(),
        "after warm, all durable create txs must be considered indexed"
    );
    assert_eq!(q.scripthash_entry_count(), n0);
    let mut heads = HashMap::new();
    q.store()
        .scripthash
        .put_create_batch_append(&to_put, &mut heads)
        .unwrap();
    assert_eq!(q.scripthash_entry_count(), n0);

    // Sample heights still on chain after disconnect.
    let sample_tip = tip_h - 1;
    for h in [0u32, 1, sample_tip / 2, sample_tip] {
        assert_reconstruct_eq(&q, h, &chain.blocks[h as usize]);
    }

    assert!(q.reconstruct_block_by_hash(&[0xab; 32]).unwrap().is_none());
    assert!(q.reconstruct_block_at_height(Height(9999)).is_err());

    let loc = q.locator_hashes().unwrap();
    assert!(!loc.is_empty());
    let headers = q
        .headers_after_locator(
            &loc[loc.len().saturating_sub(1)..],
            BlockHash::from_byte_array([0; 32]),
            2000,
        )
        .unwrap();
    assert!(!headers.is_empty());
    // Stop-hash match path (headers_after_locator early exit).
    let stop = chain.blocks[3.min(sample_tip as usize)].block_hash();
    let stopped = q
        .headers_after_locator(&[chain.blocks[0].block_hash()], stop, 50)
        .unwrap();
    assert!(!stopped.is_empty());
    assert_eq!(stopped.last().unwrap().block_hash(), stop);
    // Zero locator entry → start from genesis.
    let from_zero = q
        .headers_after_locator(
            &[BlockHash::from_byte_array([0u8; 32])],
            BlockHash::from_byte_array([0u8; 32]),
            5,
        )
        .unwrap();
    assert_eq!(from_zero.len(), 5);

    let flags = local_service_flags();
    assert!(flags.has(ServiceFlags::NETWORK));
    assert!(flags.has(ServiceFlags::WITNESS));

    // Consensus header helpers on the same pad (no second open).
    let mtp = rbitcoin_consensus::median_time_past(&q, Height(sample_tip)).unwrap();
    assert!(mtp > 0, "mtp={mtp}");
    let bits =
        rbitcoin_consensus::expected_next_bits(&q, &params, Height(sample_tip + 1), 0).unwrap();
    let tip_bits = q
        .header_at_height(Height(sample_tip))
        .unwrap()
        .unwrap()
        .1
        .bits;
    assert_eq!(
        bits.to_consensus(),
        tip_bits,
        "regtest no-retarget: next bits == tip bits"
    );
    // Idempotent ensure_header at tip.
    let tip_rec = q.get_header(tip_fk).unwrap();
    let again = q.ensure_header(&tip_rec).unwrap();
    assert_eq!(again, tip_fk);

    pin_resume_archived_bodies_after_disconnect(&q, &chain.blocks, tip_h);
    pin_reconnect_archived_run_extends_height_index(&q, &params, &chain.blocks, tip_h);
}

/// After the spend block is disconnected, a queued child of that abandoned
/// fork must not find its parent through the TipOnly wave or the leftover
/// plan: the disconnected row is not on the best chain.
fn pin_abandoned_fork_is_not_a_parent(
    q: &Query,
    params: &ChainParams,
    chain: &rbitcoin_test::MatureRegtestChain,
) {
    use bitcoin::consensus::encode::serialize;
    use rbitcoin_consensus::{
        confirm_bq_resolve_wave_capped, take_wave_items_for_load, BQ_RESOLVE_WAVE_MAX_BLOCKS,
        BQ_RESOLVE_WAVE_MAX_INPUTS,
    };

    let tip_h = chain.tip_height();
    assert_eq!(q.tip_height(), Some(Height(tip_h - 1)));
    let abandoned = chain.blocks.last().unwrap();
    let orphan_parent = abandoned.txdata[1].compute_txid();
    let child = mine_regtest_block(
        abandoned.block_hash(),
        abandoned.header.time + 600,
        tip_h + 1,
        vec![spend_anyone_can_spend(
            orphan_parent,
            0,
            Amount::from_sat(48_0000_0000),
        )],
    );
    q.block_queue_enqueue(
        tip_h + 1,
        child.block_hash().to_byte_array(),
        u64::from(tip_h) + 1,
        &serialize(&child),
    )
    .unwrap();
    let wave = confirm_bq_resolve_wave_capped(
        q,
        params,
        Milestone::NONE,
        &[tip_h + 1],
        BQ_RESOLVE_WAVE_MAX_BLOCKS,
        BQ_RESOLVE_WAVE_MAX_INPUTS,
    )
    .unwrap();
    assert_eq!(wave.stats.heights, 1);
    assert!(take_wave_items_for_load(q, &wave.items, q.lookup_taken_gen()).unwrap());
    assert!(
        wave.parent_ids
            .get(&orphan_parent.to_byte_array())
            .is_none(),
        "an abandoned-fork tx is not a TipOnly hit"
    );
    assert!(!q.block_queue_has_height(tip_h + 1));

    let block = std::sync::Arc::new(child);
    let txids: Vec<[u8; 32]> = block
        .txdata
        .iter()
        .map(|t| t.compute_txid().to_byte_array())
        .collect();
    let err = q
        .archive_plan_batch_from_wire(
            &[(Fk(u64::from(tip_h) + 1), &block, txids.as_slice())],
            q.tx_body_count() + 1,
            &InFlight::new(),
            None,
            None,
        )
        .expect_err("a disconnected leftover must not fill the parent");
    assert!(
        err.to_string().contains("parent create_fk unresolved"),
        "{err}"
    );
}

fn pin_archived_sibling_bodies(
    q: &Query,
    params: &ChainParams,
    chain: &rbitcoin_test::MatureRegtestChain,
    double_spend: &Block,
) {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::{ScriptBuf, TxOut};
    use rbitcoin_consensus::commit_class_a_block;

    let tip_h = chain.tip_height();
    let bad_hash = double_spend.block_hash().to_byte_array();
    let (bad_fk, _) = q.get_header_by_hash(&bad_hash).unwrap().unwrap();
    assert!(q.header_has_class_a_body(bad_fk.0).unwrap());
    assert!(q.is_block_archived(&bad_hash).unwrap());
    assert_eq!(q.height_of_hash(&bad_hash).unwrap(), None);
    assert!(q.clear_archived_body(&bad_hash).unwrap());
    assert!(!q.clear_archived_body(&bad_hash).unwrap());
    assert!(!q.is_block_archived(&bad_hash).unwrap());
    assert!(!q.clear_archived_body(&[0xde; 32]).unwrap());

    let mut p2tr = vec![0x51, 0x20];
    p2tr.extend_from_slice(&[0x55; 32]);
    let p2a = vec![0x51, 0x02, 0x4e, 0x73];
    let mut split = spend_anyone_can_spend(
        chain.blocks[2].txdata[0].compute_txid(),
        0,
        Amount::from_sat(1_0000_0000),
    );
    split.output = vec![
        TxOut {
            value: Amount::from_sat(1_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(p2tr),
        },
        TxOut {
            value: Amount::from_sat(240),
            script_pubkey: ScriptBuf::from_bytes(p2a),
        },
    ];
    let tip = chain.blocks.last().unwrap();
    let sibling = mine_regtest_block(
        tip.block_hash(),
        tip.header.time + 601,
        tip_h + 1,
        vec![split],
    );
    commit_class_a_block(q, params, Height(tip_h + 1), &sibling, Milestone::NONE).unwrap();
    let rebuilt = q
        .reconstruct_archived_block(&sibling.block_hash().to_byte_array())
        .unwrap()
        .expect("archived sibling");
    assert_eq!(
        serialize(&rebuilt),
        serialize(&sibling),
        "P2TR and P2A outputs rebuild to their wire scripts"
    );
    assert_eq!(q.tip_height(), Some(Height(tip_h)));
}

fn pin_reconnect_archived_run_extends_height_index(
    q: &Query,
    params: &ChainParams,
    blocks: &[Block],
    tip_h: u32,
) {
    use rbitcoin_consensus::confirm_wire_run;

    let from_h = q.tip_height().unwrap().0;
    assert_eq!(
        q.height_of_hash(&blocks[from_h as usize].block_hash().to_byte_array())
            .unwrap(),
        Some(Height(from_h))
    );
    let _ = q.confirm_stats().take_window();
    let run: Vec<_> = (from_h + 1..=tip_h)
        .map(|h| (Height(h), blocks[h as usize].clone()))
        .collect();
    confirm_wire_run(q, params, Milestone::NONE, &run).unwrap();
    assert_eq!(q.tip_height(), Some(Height(tip_h)));
    let merged = q.confirm_stats().take_window();
    assert_eq!(
        merged.height_index_full_n, 0,
        "a merged confirm extends the height index, it does not walk 0..=tip"
    );
    assert_eq!(merged.height_index_delta_n, u64::from(tip_h - from_h));
    assert_eq!(q.process_owned_size_snapshot().h2h_keys, tip_h as usize + 1);
    for h in from_h..=tip_h {
        assert_eq!(
            q.height_of_hash(&blocks[h as usize].block_hash().to_byte_array())
                .unwrap(),
            Some(Height(h))
        );
    }
}

fn pin_resume_archived_bodies_after_disconnect(q: &Query, blocks: &[Block], tip_h: u32) {
    let from_h = tip_h - 4;
    while q.tip_height().map(|h| h.0).unwrap() > from_h {
        q.disconnect_tip().unwrap();
    }
    assert_eq!(q.tip_height(), Some(Height(from_h)));
    let from_hash = q.header_at_height(Height(from_h)).unwrap().unwrap().1.hash;
    let path = q
        .resume_work_path_after_tip(from_hash, from_h, 64)
        .expect("resume");
    assert!(
        path.len() >= 4,
        "expected ≥4 headers after tip, got {}",
        path.len()
    );
    assert!(
        path.iter().all(|e| e.has_body),
        "all resume entries should have Class A bodies"
    );
    for i in 0..4u32 {
        let h = from_h + 1 + i;
        let e = path
            .iter()
            .find(|e| e.height == h)
            .unwrap_or_else(|| panic!("missing resume height {h}"));
        assert_eq!(e.hash, blocks[h as usize].block_hash().to_byte_array());
        assert!(q.is_block_archived(&e.hash).unwrap());
    }
}

#[allow(clippy::cognitive_complexity)] // one pad, many scripthash view arms
fn pin_scripthash_views_on_pad(
    q: &Query,
    chain: &rbitcoin_test::MatureRegtestChain,
    slot: &mut Option<std::sync::Arc<rbitcoin_query::ShJoinSlot>>,
) {
    use rbitcoin_query::{HistoryFilter, HistoryOrder};
    use rbitcoin_store::script_hash;

    let sh = script_hash(&[0x51]);
    let tip_h = chain.tip_height();
    let spend_block = &chain.blocks[chain.spend_height as usize];
    let tip_cb = spend_block.txdata[0].compute_txid().to_byte_array();
    let spend_txid = spend_block.txdata[1].compute_txid().to_byte_array();
    let full = q.scripthash_history(&sh).unwrap();
    assert_eq!(
        full.len() as u32,
        tip_h + 1,
        "an OP_TRUE coinbase at every height past genesis, plus the spend"
    );
    assert_eq!(
        q.scripthash_history_filtered(&sh, &HistoryFilter::open())
            .unwrap()
            .rows,
        full
    );
    let heights = |f: &HistoryFilter| -> Vec<i64> {
        q.scripthash_history_filtered(&sh, f)
            .unwrap()
            .rows
            .iter()
            .map(|i| i.height)
            .collect()
    };
    assert_eq!(heights(&HistoryFilter::height_window(1, Some(3))), [1, 2]);
    let top = i64::from(tip_h);
    assert_eq!(
        heights(&HistoryFilter::height_window(tip_h - 1, None)),
        [top - 1, top, top]
    );
    let newest = HistoryFilter {
        from_height: 0,
        to_height: None,
        limit: Some(2),
        after_txid: None,
        order: HistoryOrder::NewestFirst,
    };
    assert_eq!(heights(&newest), [top, top]);

    let view = q.pin_chain_view().unwrap().unwrap();
    let rows = q
        .scripthash_history_summary_filtered_in(
            &sh,
            &HistoryFilter::esplora_chain_page(None),
            &view,
        )
        .unwrap()
        .rows;
    assert_eq!(rows.len(), 25);
    let value_of = |txid: [u8; 32]| rows.iter().find(|r| r.txid == txid).unwrap().value;
    assert_eq!(value_of(tip_cb), 50_0000_0000);
    assert_eq!(
        value_of(spend_txid),
        -1_0000_0000,
        "net value is funded minus spent on the same scripthash"
    );

    let stats = q.scripthash_chain_stats(&sh).unwrap();
    assert_eq!(stats.tx_count as usize, full.len());
    assert_eq!(stats.funded_txo_count, tip_h + 1);
    assert_eq!(
        stats.funded_txo_sum,
        i64::from(tip_h) * 50_0000_0000 + 49_0000_0000
    );
    assert_eq!(stats.spent_txo_count, 1);
    assert_eq!(stats.spent_txo_sum, 50_0000_0000);
    let balance = q.scripthash_balance(&sh).unwrap();
    assert_eq!(
        balance.confirmed,
        stats.funded_txo_sum - stats.spent_txo_sum
    );

    let utxos = q.scripthash_listunspent(&sh).unwrap();
    assert_eq!(utxos.len() as u32, tip_h);

    let scanned = q.scan_unspent_scripts(&[vec![0x51]]).unwrap();
    assert_eq!(scanned.len(), utxos.len());
    assert_eq!(
        scanned
            .iter()
            .filter(|u| !u.coinbase)
            .map(|u| u.txid)
            .collect::<Vec<_>>(),
        [spend_txid]
    );

    assert_eq!(q.scripthash_balance_slot(&sh, slot).unwrap(), balance);
    assert_eq!(q.scripthash_history_slot(&sh, slot).unwrap(), full);
    assert_eq!(q.scripthash_listunspent_slot(&sh, slot).unwrap(), utxos);
    assert_eq!(q.scripthash_chain_stats_slot(&sh, slot).unwrap(), stats);

    assert_eq!(
        q.scripthash_tx_fks_at_height(&sh, Height(tip_h)).unwrap(),
        q.block_tx_fks(Height(tip_h)).unwrap(),
        "tip coinbase creates and the spend spends the scripthash"
    );
    assert!(
        !q.scripthash_touched_at_height(&sh, Height::GENESIS)
            .unwrap(),
        "the genesis coinbase pays a pubkey, not OP_TRUE"
    );
    assert!(q.scripthash_touched_at_height(&sh, Height(1)).unwrap());
    assert!(!q
        .scripthash_touched_at_height(&script_hash(&[0x52]), Height(tip_h))
        .unwrap());
    // The shared per-block touch set must agree with the per-hash probe at
    // every height (creates, spends, and blocks that never touch it).
    for h in 0..=tip_h {
        let touch = q.block_touch(Height(h)).unwrap();
        for probe in [sh, script_hash(&[0x52])] {
            assert_eq!(
                q.scripthash_touched_by(&probe, &touch).unwrap(),
                q.scripthash_touched_at_height(&probe, Height(h)).unwrap(),
                "height {h}"
            );
        }
    }

    q.set_spend_index(false);
    let no_spends = q.scripthash_listunspent(&sh).unwrap();
    q.set_spend_index(true);
    assert_eq!(
        no_spends, utxos,
        "with the spend index off the join falls back to the outpoint spend check"
    );
}

#[allow(clippy::cognitive_complexity)] // one pad, many block/tx surface arms
fn pin_block_and_tx_surface_on_pad(q: &Query, chain: &rbitcoin_test::MatureRegtestChain) {
    use bitcoin::consensus::encode::serialize;
    use rbitcoin_consensus::header_to_record;
    use rbitcoin_query::ConfirmPrepared;

    let spend_h = Height(chain.spend_height);
    let spend_block = &chain.blocks[chain.spend_height as usize];
    let tip_hash = spend_block.block_hash().to_byte_array();
    let fks = q.block_tx_fks(spend_h).unwrap();
    let txids: Vec<[u8; 32]> = spend_block
        .txdata
        .iter()
        .map(|t| t.compute_txid().to_byte_array())
        .collect();
    let cb1 = chain.matured_coinbase_txid.to_byte_array();
    let cb1_fk = q.block_tx_fks(Height(1)).unwrap()[0];

    assert_eq!(q.block_txids(spend_h).unwrap(), txids);
    assert_eq!(q.block_txid_at(spend_h, 1).unwrap(), txids[1]);
    assert!(q.block_txid_at(spend_h, 2).is_err());
    let proof = q.merkle_proof(spend_h, &txids[1]).unwrap();
    assert_eq!((proof.block_height, proof.pos), (spend_h.0, 1));
    assert_eq!(proof.merkle, [txids[0]]);
    assert!(q.merkle_proof(spend_h, &[0xff; 32]).is_err());
    assert!(q.block_tx_fks(Height(9999)).is_err());
    assert!(q.block_txids(Height(9999)).is_err());

    for (fk, tx) in fks.iter().zip(&spend_block.txdata) {
        assert_eq!(q.tx_wire_bytes(*fk).unwrap(), serialize(tx));
        assert_eq!(&q.reconstruct_tx(*fk).unwrap(), tx);
    }

    let archived = q.reconstruct_archived_block(&tip_hash).unwrap().unwrap();
    assert_eq!(serialize(&archived), serialize(spend_block));

    assert!(q.reconstruct_archived_block(&[0x11; 32]).unwrap().is_none());
    let (tip_fk, tip_rec) = q.get_header_by_hash(&tip_hash).unwrap().unwrap();
    assert!(q
        .reconstruct_archived_block_from_parts(tip_rec, vec![])
        .is_err());
    assert_eq!(
        q.header_tx_fks(tip_fk, Some(&tip_hash)).unwrap(),
        Some(fks.clone())
    );

    let spend_rec = q.get_tx(fks[1]).unwrap();
    assert_eq!(
        q.tx_input_at_fk(fks[1], &spend_rec, 0).unwrap().create_fk,
        cb1_fk
    );
    assert!(q.tx_input_at_fk(fks[1], &spend_rec, 1).is_err());
    assert!(q.tx_input(&spend_rec, 1).is_err());

    assert_eq!(q.tx_output_at_fk(fks[1], 0).unwrap().value, 49_0000_0000);

    assert!(q.tx_output_at_fk(fks[1], 1).is_err());
    assert_eq!(q.unspent_create_vouts(fks[1], &[0]).unwrap(), [0]);
    assert!(q.unspent_create_vouts(cb1_fk, &[0]).unwrap().is_empty());
    assert_eq!(q.spenders_raw(&cb1, 0).unwrap().len(), 1);
    let unknown = TxRecord {
        txid: [0xcd; 32],
        ..spend_rec
    };
    assert!(q.tx_output(&unknown, 0).is_err());

    assert_eq!(q.confirm_block(spend_h, &tip_hash).unwrap(), tip_fk);
    assert!(q.confirm_blocks_run(&[]).unwrap().is_empty());
    let prepared = |height: u32, header_fk: Fk| ConfirmPrepared {
        height: Height(height),
        header_fk,
        tx_fks: vec![fks[0]],
    };
    for bad in [
        vec![prepared(spend_h.0 + 1, Fk::NULL)],
        vec![prepared(spend_h.0 + 5, tip_fk)],
        vec![
            prepared(spend_h.0 + 1, tip_fk),
            prepared(spend_h.0 + 3, tip_fk),
        ],
    ] {
        assert!(q.confirm_blocks_run(&bad).is_err(), "{:?}", bad[0].height);
    }
    assert_eq!(q.tip_height(), Some(spend_h));

    assert!(q.header_has_class_a_body(tip_fk.0).unwrap());
    assert!(!q.header_has_class_a_body(0).unwrap());
    let orphan = mine_regtest_block(
        chain.blocks[5].block_hash(),
        chain.blocks[6].header.time + 1,
        6,
        vec![],
    );
    let orphan_hash = orphan.block_hash().to_byte_array();
    let orphan_rec = header_to_record(Fk::NULL, &orphan.header, orphan_hash);
    let orphan_fk = q.ensure_header(&orphan_rec).unwrap();
    assert_eq!(q.ensure_header(&orphan_rec).unwrap(), orphan_fk);
    assert!(!q.header_has_class_a_body(orphan_fk.0).unwrap());
    assert!(!q.is_block_archived(&orphan_hash).unwrap());
    assert_eq!(q.height_of_hash(&orphan_hash).unwrap(), None);
    assert_eq!(q.archived_block_count().unwrap(), u64::from(spend_h.0) + 1);

    q.invalidate_height_by_hash_index();
    assert_eq!(
        q.height_of_hash(&chain.blocks[1].block_hash().to_byte_array())
            .unwrap(),
        Some(Height(1))
    );
    assert!(q
        .resume_work_path_after_tip(tip_hash, spend_h.0, 0)
        .unwrap()
        .is_empty());
    assert!(q
        .resume_work_path_after_tip([0xaa; 32], 0, 10)
        .unwrap()
        .is_empty());
    q.archive_class_a_from_wire(&[]).unwrap();

    assert!(!q.confirm_cancelled());
    q.request_confirm_cancel();
    assert!(q.confirm_cancelled());
    q.clear_confirm_cancel();
    assert!(!q.confirm_cancelled());
    q.flush_header_archive().unwrap();
    q.flush_for_shutdown().unwrap();
}

fn pin_same_run_create_then_spend(
    q: &Query,
    params: &ChainParams,
    ms: Milestone,
    tip: BlockHash,
    tip_time: u32,
    parent_cb: bitcoin::Txid,
    create_h: u32,
) -> (BlockHash, u32) {
    use rbitcoin_consensus::{commit_class_a_run, confirm_wire_run};

    let mk_parent = spend_anyone_can_spend(parent_cb, 0, Amount::from_sat(49_0000_0000));
    let b_create = mine_regtest_block(tip, tip_time + 600, create_h, vec![mk_parent]);
    let parent_txid = b_create.txdata[1].compute_txid();
    let spend_h = create_h + 1;
    let spend_parent = spend_anyone_can_spend(parent_txid, 0, Amount::from_sat(48_0000_0000));
    let b_spend = mine_regtest_block(
        b_create.block_hash(),
        b_create.header.time + 600,
        spend_h,
        vec![spend_parent],
    );
    let run = [
        (Height(create_h), b_create),
        (Height(spend_h), b_spend.clone()),
    ];
    commit_class_a_run(q, params, &run, ms).unwrap();
    confirm_wire_run(q, params, ms, &run)
        .expect("same-run create then spend must confirm (open reserve not a deadlock)");
    assert_eq!(q.tip_height(), Some(Height(spend_h)));
    assert!(
        q.is_outpoint_spent(parent_txid.as_byte_array(), 0).unwrap(),
        "in-batch parent must be spent after multi-block run"
    );
    (b_spend.block_hash(), b_spend.header.time)
}

fn pin_both_vouts_of_one_input_parent(
    q: &Query,
    params: &ChainParams,
    ms: Milestone,
    tip: BlockHash,
    tip_time: u32,
    cb: bitcoin::Txid,
    split_h: u32,
) -> (BlockHash, u32) {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_consensus::{commit_class_a_block, commit_class_a_run, confirm_wire_run};
    use rbitcoin_test::mine::{spend_many_anyone_can_spend, split_anyone_can_spend};

    let split = split_anyone_can_spend(
        cb,
        0,
        &[
            Amount::from_sat(20_0000_0000),
            Amount::from_sat(29_0000_0000),
        ],
    );
    let b_split = mine_regtest_block(tip, tip_time + 600, split_h, vec![split]);
    let parent_txid = b_split.txdata[1].compute_txid();
    let merge_h = split_h + 1;
    let t1 = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: parent_txid,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: parent_txid,
                    vout: 1,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(20_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            TxOut {
                value: Amount::from_sat(28_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
        ],
    };
    let t1_txid = t1.compute_txid();
    let t2 = spend_many_anyone_can_spend(
        &[(t1_txid, 0), (t1_txid, 1)],
        Amount::from_sat(47_0000_0000),
    );
    let t2_txid = t2.compute_txid();
    let t3 = spend_many_anyone_can_spend(&[(t2_txid, 0)], Amount::from_sat(46_0000_0000));
    let b_merge = mine_regtest_block(
        b_split.block_hash(),
        b_split.header.time + 600,
        merge_h,
        vec![t1, t2, t3],
    );
    commit_class_a_run(
        q,
        params,
        &[
            (Height(split_h), b_split.clone()),
            (Height(merge_h), b_merge.clone()),
        ],
        ms,
    )
    .unwrap();
    confirm_wire_run(
        q,
        params,
        ms,
        &[
            (Height(split_h), b_split),
            (Height(merge_h), b_merge.clone()),
        ],
    )
    .expect("mainnet-546-shaped multi-block confirm must not MissingPrevout");
    assert_eq!(q.tip_height(), Some(Height(merge_h)));
    assert!(q.is_outpoint_spent(parent_txid.as_byte_array(), 0).unwrap());
    assert!(q.is_outpoint_spent(parent_txid.as_byte_array(), 1).unwrap());

    let t3_txid = b_merge.txdata[3].compute_txid();
    let next_h = merge_h + 1;
    let spend = spend_many_anyone_can_spend(&[(t3_txid, 0)], Amount::from_sat(45_0000_0000));
    let b_next = mine_regtest_block(
        b_merge.block_hash(),
        b_merge.header.time + 600,
        next_h,
        vec![spend],
    );
    commit_class_a_block(q, params, Height(next_h), &b_next, ms).unwrap();
    let next = (b_next.block_hash(), b_next.header.time);
    confirm_wire_run(q, params, ms, &[(Height(next_h), b_next)])
        .expect("cross-batch tx.head create_fk resolve must work");
    assert_eq!(q.tip_height(), Some(Height(next_h)));
    next
}

fn pin_txstat_rows_after_write(q: &Query, run: &[(Height, Block)], spend_h: u32) {
    use rbitcoin_store::TxStatRow;

    let genesis_fk = q.block_tx_fks(Height::GENESIS).unwrap()[0];
    let genesis = regtest_genesis();
    let g = q.get_txstat(genesis_fk).unwrap().expect("genesis txstat");
    assert_eq!(g.fee_sat, 0);
    assert_eq!(g.size() as usize, genesis.txdata[0].total_size());
    assert_eq!(g.weight(), genesis.txdata[0].weight().to_wu());

    let block = &run.last().unwrap().1;
    let spend = &block.txdata[1];
    let fks = q.block_tx_fks(Height(spend_h)).unwrap();
    let cb1_fk = q.block_tx_fks(Height(1)).unwrap()[0];
    let row = q.get_txstat(fks[1]).unwrap().expect("spend txstat");
    assert_eq!(row.fee_sat, 1_0000_0000, "fee from the load-stage assemble");
    assert_eq!(row.size() as usize, spend.total_size());
    assert_eq!(row.weight(), spend.weight().to_wu());
    assert_eq!(q.store().input_n_in(fks[1]).unwrap(), Some(1));
    let rec = q.get_tx(fks[1]).unwrap();
    let ins = q.tx_input_run_class_a(fks[1], &rec).unwrap();
    assert_eq!(ins.len(), 1);
    assert_eq!(ins[0].create_fk, cb1_fk);
    let no_io = TxRecord {
        input_count: 0,
        output_count: 0,
        ..rec
    };
    assert!(q.tx_input_run_class_a(fks[1], &no_io).unwrap().is_empty());

    let zero = TxStatRow {
        fee_sat: 0,
        base: 0,
        wit_extra: 0,
    };
    for &fk in &fks {
        q.store().write_txstat_row(fk, &zero).unwrap();
    }
    assert!(q.get_txstat(fks[1]).unwrap().is_none());
    let empty = Block {
        header: block.header,
        txdata: vec![],
    };
    for (h, needle) in [
        (Height(9999), "stamp txstat missing header"),
        (Height(spend_h), "stamp txstat fk count"),
    ] {
        let err = q.stamp_txstat_from_block(h, &empty).unwrap_err();
        assert!(err.to_string().contains(needle), "{err}");
    }
    q.stamp_txstat_from_block(Height(spend_h), block).unwrap();
    assert_eq!(q.get_txstat(fks[1]).unwrap(), Some(row));
    assert_eq!(q.get_txstat(fks[0]).unwrap().unwrap().fee_sat, 0);
    assert!(q.confirm_block(Height(9), &[0xde; 32]).is_err());
}

/// With the spend index off, Class C commits without annotating the spend.
/// Accepting the same block again at that height must finish the annotate.
fn pin_already_at_height_retry_annotates_spend(
    q: &Query,
    params: &ChainParams,
    ms: Milestone,
    (tip, tip_time): (BlockHash, u32),
    cb: bitcoin::Txid,
    h: u32,
) {
    q.set_spend_index(false);
    let spend = spend_anyone_can_spend(cb, 0, Amount::from_sat(49_0000_0000));
    let b = mine_regtest_block(tip, tip_time + 600, h, vec![spend]);
    accept_and_connect_block(q, params, Height(h), &b, ms).unwrap();
    assert!(
        q.spenders(cb.as_byte_array(), 0).unwrap().is_empty(),
        "spend index off: Class C does not annotate"
    );
    q.set_spend_index(true);
    accept_and_connect_block(q, params, Height(h), &b, ms).expect("already-at-height retry");
    assert_eq!(q.tip_height(), Some(Height(h)));
    assert_eq!(
        q.spenders(cb.as_byte_array(), 0).unwrap().len(),
        1,
        "the retry finishes the spend annotate"
    );
}

/// Split load → scripts → write (IBD pipeline stages) on a spend run.
/// Also exercises parent pin stats + tip advance, and load ready timeout/cancel.
#[test]
fn three_stage_confirm_and_parent_pin_surface() {
    use rbitcoin_consensus::{
        accept_and_connect_block, commit_class_a_run, confirm_scripts_phase,
        confirm_wire_load_phase, confirm_write_phase, ChainParams, Milestone, ScriptPreverified,
    };
    use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis, spend_anyone_can_spend};

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create_tiny(td.store_path()).unwrap();
    q.enter_direct_index_mode().unwrap();
    let ms = Milestone::NONE;
    let params = ChainParams::regtest();
    assert!(
        params.csv_active_at(1),
        "regtest CSV from height 1 — mid-batch BIP113 MTP uses header plans"
    );
    let maturity = params.coinbase_maturity();
    let none = ScriptPreverified::new();

    let genesis = regtest_genesis();
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;

    let b1 = mine_regtest_block(tip, tip_time + 600, 1, vec![]);
    let cb1 = b1.txdata[0].compute_txid();
    tip = b1.block_hash();
    tip_time = b1.header.time;

    let last_pad = maturity + 1;
    let mut run: Vec<(Height, bitcoin::Block)> = vec![(Height(1), b1)];
    for h in 2..=last_pad {
        let b = mine_regtest_block(tip, tip_time + 600, h, vec![]);
        tip = b.block_hash();
        tip_time = b.header.time;
        run.push((Height(h), b));
    }

    let spend_h = last_pad + 1;
    let spend = spend_anyone_can_spend(cb1, 0, Amount::from_sat(49_0000_0000));
    let b_spend = mine_regtest_block(tip, tip_time + 600, spend_h, vec![spend]);
    run.push((Height(spend_h), b_spend));
    commit_class_a_run(&q, &params, &run, ms).unwrap();

    // LOAD (tip still genesis — mid-batch spend MTP must use header plans, not store confirmed[])
    let mat = confirm_wire_load_phase(&q, &params, ms, &run, &none).unwrap_or_else(|e| {
        panic!(
            "multi-block load with mid-batch spend must not fail BIP68 MTP (got {e}); \
             store-only median_time_past would BadPrev on unconfirmed prev heights"
        );
    });
    assert!(!mat.batch.is_empty());
    assert!(mat.work_ns > 0);
    let heights = mat.batch.heights_hashes();
    assert_eq!(heights.len(), run.len());
    assert_eq!(mat.batch.len(), run.len());

    // SCRIPTS
    let ok = confirm_scripts_phase(mat.batch).expect("scripts");

    // WRITE
    let fks = confirm_write_phase(&q, &params, ms, ok.batch).expect("write");
    assert_eq!(fks.len(), run.len());
    assert_eq!(q.tip_height(), Some(Height(spend_h)));
    assert!(q.is_outpoint_spent(cb1.as_byte_array(), 0).unwrap());
    pin_txstat_rows_after_write(&q, &run, spend_h);

    let write = q.confirm_stats().last_write_phases();
    assert!(
        write.n_blocks as usize >= run.len(),
        "write meter must name the batch: {write:?}"
    );
    assert!(write.wall_ns > 0, "write wall must move: {write:?}");
    let pin = q.confirm_stats().last_pin_phases();
    assert!(
        pin.pin_plan_n > 0 || pin.pin_new_n > 0,
        "load pin meter must move: {pin:?}"
    );
    let w = q.confirm_stats().take_window();
    assert!(
        w.phase_blocks >= run.len() as u64,
        "phase_blocks must count the run: {}",
        w.phase_blocks
    );
    assert!(
        w.load_blocks >= run.len() as u64,
        "load_blocks must count the run: {}",
        w.load_blocks
    );
    assert!(
        w.script_jobs > 0 || w.script_ns > 0 || w.script_skip_mempool > 0,
        "script meter must move: jobs={} ns={} skip={}",
        w.script_jobs,
        w.script_ns,
        w.script_skip_mempool
    );
    let other = Query::open_or_create_tiny(td.path().join("other")).unwrap();
    let idle = other.confirm_stats().take_window();
    assert_eq!(
        (
            idle.phase_blocks,
            idle.load_blocks,
            idle.load_ns,
            idle.script_ns
        ),
        (0, 0, 0, 0),
        "a second engine's window does not see this engine's confirm"
    );
    assert_eq!(q.confirm_stats().take_window().load_blocks, 0);

    // Tip advance prunes plans/headers ≤ tip (body LRU retains under budget).
    q.advance_parent_cache_tip(spend_h);
    // Combined load entry on empty: reject empty.
    let empty = confirm_wire_load_phase(&q, &params, ms, &[], &none);
    assert!(empty.is_err());

    let cb2 = run[1].1.txdata[0].compute_txid();
    let cb3 = run[2].1.txdata[0].compute_txid();
    let tip = run.last().unwrap().1.block_hash();
    let tip_time = run.last().unwrap().1.header.time;
    let (tip, tip_time) =
        pin_same_run_create_then_spend(&q, &params, ms, tip, tip_time, cb2, spend_h + 1);
    let tip = pin_both_vouts_of_one_input_parent(&q, &params, ms, tip, tip_time, cb3, spend_h + 3);
    let cb4 = run[3].1.txdata[0].compute_txid();
    pin_already_at_height_retry_annotates_spend(&q, &params, ms, tip, cb4, spend_h + 6);
}

/// Load may claim tip+1 while earlier heights are still in-flight (not written).
///
/// Signet IBD failed at height 11 with permanent BadPrev: assemble_run fell back
/// to store `confirmed[prev]` because the MTP window was not *all* header plans
/// (genesis / tip-GC'd heights missing), even though parent height 10 had a plan
/// from the prior load batch. Mixed store(≤tip)+plan(>tip) must succeed.
#[test]
fn confirm_load_ahead_of_write_does_not_badprev() {
    use rbitcoin_consensus::{
        accept_and_connect_block, commit_class_a_block, confirm_scripts_phase,
        confirm_wire_load_phase, confirm_wire_load_phase_pipelined, confirm_write_phase,
        ChainParams, Milestone, ScriptPreverified, WireLoadPipeline,
    };
    use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis};

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create_tiny(td.store_path()).unwrap();
    q.enter_direct_index_mode().unwrap();
    let ms = Milestone::NONE;
    let params = ChainParams::regtest();
    let none = ScriptPreverified::new();

    let genesis = regtest_genesis();
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;

    // Archive 20 thin coinbase blocks (same shape as early signet).
    let mut all: Vec<(Height, bitcoin::Block)> = Vec::with_capacity(20);
    for h in 1u32..=20 {
        let b = mine_regtest_block(tip, tip_time + 600, h, vec![]);
        commit_class_a_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
        all.push((Height(h), b));
    }
    assert_eq!(q.tip_height(), Some(Height::GENESIS));

    // Batch A: load heights 1..=10 (do not write yet — parent plans stay above tip).
    let batch_a = &all[..10];
    let mat_a = confirm_wire_load_phase(&q, &params, ms, batch_a, &none)
        .expect("load 1..=10 must assemble with tip=0");
    assert_eq!(mat_a.batch.len(), 10);
    assert_eq!(
        q.tip_height(),
        Some(Height::GENESIS),
        "load must not advance tip"
    );

    // Batch B: load 11..=20 while tip still genesis (IBD load queue depth ≥ 2).
    // Regression: used to permanent-BadPrev on height 11 (prev not in confirmed[]).
    let batch_b = &all[10..];
    let inflight = rbitcoin_query::InFlight::new();
    let pipe = WireLoadPipeline {
        path_lo: 11,
        parent_hash: Some(all[9].1.block_hash().to_byte_array()),
        next_tx_start: 0,
        in_flight: &inflight,
        skeleton: None,
        carried_need: Vec::new(),
        carried_header_fks: Vec::new(),
        carried_header_hashes: Vec::new(),
    };
    let mat_b = confirm_wire_load_phase_pipelined(&q, &params, ms, batch_b, &none, Some(&pipe))
        .unwrap_or_else(|e| {
            panic!("load 11..=20 ahead of write must not fail (got {e}); tip still genesis");
        });
    assert_eq!(mat_b.batch.len(), 10);
    assert_eq!(
        mat_b.batch.heights_hashes()[0].0,
        11,
        "second batch starts at 11"
    );

    // Finish pipeline: scripts + write A then B.
    let ok_a = confirm_scripts_phase(mat_a.batch).expect("scripts A");
    confirm_write_phase(&q, &params, ms, ok_a.batch).expect("write A");
    assert_eq!(q.tip_height(), Some(Height(10)));

    let ok_b = confirm_scripts_phase(mat_b.batch).expect("scripts B");
    confirm_write_phase(&q, &params, ms, ok_b.batch).expect("write B");
    assert_eq!(q.tip_height(), Some(Height(20)));

    // Tip GC dropped plans ≤ 20. Next load's MTP window is store confirmed[].
    let mut after_gc: Vec<(Height, bitcoin::Block)> = Vec::with_capacity(12);
    for h in 21u32..=32 {
        let b = mine_regtest_block(tip, tip_time + 600, h, vec![]);
        commit_class_a_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
        after_gc.push((Height(h), b));
    }
    assert_eq!(q.tip_height(), Some(Height(20)));
    let mat_c = confirm_wire_load_phase(&q, &params, ms, &after_gc, &none).unwrap_or_else(|e| {
        panic!("load after tip_gc must use store for MTP parents (got {e})");
    });
    assert_eq!(mat_c.batch.heights_hashes()[0].0, 21);
    let ok_c = confirm_scripts_phase(mat_c.batch).expect("scripts C");
    confirm_write_phase(&q, &params, ms, ok_c.batch).expect("write C");
    assert_eq!(q.tip_height(), Some(Height(32)));
}

/// BlockCache + MempoolHub public surfaces used by P2P tip mode / Electrum.
#[allow(clippy::cognitive_complexity)] // one fixture, many cache/hub arms
#[test]
fn block_cache_and_mempool_hub_surface() {
    use bitcoin::hashes::Hash;
    use rbitcoin_net::{BlockCache, MempoolHub};
    use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis, spend_anyone_can_spend};
    use std::sync::Arc;

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create_tiny(td.store_path()).unwrap();
    q.enter_direct_index_mode().unwrap();
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;
    let maturity = params.coinbase_maturity();

    let genesis = regtest_genesis();
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;
    let mut blocks = vec![genesis.clone()];
    let b1 = mine_regtest_block(tip, tip_time + 600, 1, vec![]);
    let cb1_txid = b1.txdata[0].compute_txid();
    accept_and_connect_block(&q, &params, Height(1), &b1, ms).unwrap();
    tip = b1.block_hash();
    tip_time = b1.header.time;
    blocks.push(b1);
    for h in 2..=maturity + 1 {
        let b = mine_regtest_block(tip, tip_time + 600, h, vec![]);
        accept_and_connect_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
        blocks.push(b);
    }

    // BlockCache: push chain, locator, headers, truncate, depth eviction.
    let cache = BlockCache::with_body_depth(4);
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
    for b in &blocks {
        cache.push_best(b.clone()).unwrap();
    }
    assert!(!cache.is_empty());
    assert_eq!(cache.tip_hash(), Some(tip));
    assert_eq!(cache.tip_height(), Some(maturity + 1));
    assert!(cache.get_block(&tip).is_some());
    assert!(cache.get_header(&tip).is_some());
    assert!(cache.hash_at_height(0).is_some());
    assert!(cache.header_at_height(maturity + 1).is_some());
    // Bodies outside depth window dropped; genesis body gone when chain > depth.
    assert!(
        cache.get_block(&blocks[0].block_hash()).is_none(),
        "body depth eviction"
    );
    assert!(cache.hash_at_height(0).is_some(), "hash chain retained");
    let loc = cache.locator();
    assert!(!loc.is_empty());
    let stop = BlockHash::from_byte_array([0u8; 32]);
    let hdrs = cache.headers_after_locator(&loc[loc.len().saturating_sub(1)..], stop);
    assert!(!hdrs.is_empty());
    // Bad extension rejected.
    let mut bad = blocks.last().unwrap().clone();
    bad.header.prev_blockhash = BlockHash::from_byte_array([0xee; 32]);
    assert!(cache.push_best(bad).is_err());
    cache.truncate_to_height(2);
    assert!(cache.tip_height().unwrap() <= 2);
    cache.clear();
    assert!(cache.is_empty());
    let empty = BlockCache::new();
    assert!(!empty.locator().is_empty());
    assert!(empty
        .headers_after_locator(&[], BlockHash::from_byte_array([0u8; 32]))
        .is_empty());

    // MempoolHub: accept a real mature coinbase spend via Query UTXO provider.
    let q_arc = Arc::new(q);
    let hub =
        MempoolHub::open_with_weight(td.path().join("mempool"), Arc::clone(&q_arc), 50_000_000)
            .unwrap();
    assert!(!hub.relay_enabled());
    hub.set_relay_enabled(true);
    assert!(hub.relay_enabled());
    assert_eq!(hub.live_count(), 0);
    let _ = hub.generation();
    let _ = hub.subscribe_announces();
    let _ = hub.fee_histogram();
    let _ = hub.estimate_fee_btc_per_kb(6);
    let _ = MempoolHub::relay_fee_btc_per_kb();
    let sh = {
        use rbitcoin_store::script_hash;
        script_hash(&[0x51])
    };
    assert!(hub.scripthash_mempool(&sh).is_empty());
    assert_eq!(hub.scripthash_unconfirmed_delta(&sh).unwrap(), 0);

    let spend = spend_anyone_can_spend(cb1_txid, 0, Amount::from_sat(49_0000_0000));
    let r = hub
        .accept_tx(&spend)
        .expect("mempool accept mature coinbase spend");
    assert!(hub.contains(&r.txid));
    assert!(hub.get_tx(&r.txid).is_some());
    assert_eq!(hub.live_count(), 1);
    assert!(!hub.list_live().is_empty());
    assert!(
        !hub.scripthash_mempool(&sh).is_empty()
            || hub.scripthash_unconfirmed_delta(&sh).unwrap() != 0
    );
    hub.flush().unwrap();
    let _ = hub.compact();
    assert_eq!(hub.remove_for_block(&[r.txid]), 1);
    assert_eq!(hub.live_count(), 0);
    assert!(hub.reorg_reaccept(std::slice::from_ref(&spend)) >= 1);
    let _ = hub.accept_package(std::slice::from_ref(&spend));
    // Confirmed UTXO still readable via query (provider path used by accept).
    let b2 = q_arc.reconstruct_block_at_height(Height(2)).unwrap();
    let cb2 = b2.txdata[0].compute_txid().to_byte_array();
    assert!(q_arc.get_tx_by_txid(&cb2).unwrap().is_some());
}

// ─── Unified wire pipeline (raw block → validated tip) ───────────────────────

/// Multi-height raw wire → tip via split load/scripts/commit (no pre-archive reload).
#[test]
fn unified_wire_pipeline_multi_block_to_tip() {
    use rbitcoin_consensus::{
        commit_class_a_block, confirm_scripts_phase, confirm_wire_load_phase, confirm_wire_run,
        confirm_write_phase, ChainParams, Milestone, ScriptPreverified,
    };

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create_tiny(td.store_path()).unwrap();
    q.enter_direct_index_mode().unwrap();
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;

    let genesis = regtest_genesis();
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;

    let b1 = mine_regtest_block(tip, tip_time + 600, 1, vec![]);
    commit_class_a_block(&q, &params, Height(1), &b1, ms).unwrap();
    assert!(q
        .is_block_archived(&b1.block_hash().to_byte_array())
        .unwrap());
    assert_eq!(
        q.tip_height(),
        Some(Height::GENESIS),
        "Class A alone does not move the tip"
    );
    let n_before = q.tx_body_count();
    commit_class_a_block(&q, &params, Height(1), &b1, ms).unwrap();
    assert_eq!(
        q.tx_body_count(),
        n_before,
        "a second archive does not re-append"
    );
    pin_block_size_weight_from_txstat(&q, &b1);
    confirm_wire_run(&q, &params, ms, &[(Height(1), b1.clone())]).unwrap();
    assert_eq!(q.tip_height(), Some(Height(1)));
    assert_eq!(
        q.tx_body_count(),
        n_before,
        "confirm must not re-append Class A already on disk"
    );
    let _ = confirm_wire_run(&q, &params, ms, &[(Height(1), b1.clone())]);
    assert_eq!(q.tip_height(), Some(Height(1)));
    assert_eq!(q.tx_body_count(), n_before);
    assert!(
        confirm_wire_run(&q, &params, ms, &[]).is_err(),
        "empty confirm_wire_run must fail without advancing tip"
    );
    assert_eq!(q.tip_height(), Some(Height(1)));
    tip = b1.block_hash();
    tip_time = b1.header.time;
    pin_confirm_refuses_without_advancing_tip(&q, &params, ms, &b1);

    let mut batch: Vec<(Height, bitcoin::Block)> = Vec::new();
    for h in 2u32..=4 {
        let b = mine_regtest_block(tip, tip_time + 600, h, vec![]);
        tip = b.block_hash();
        tip_time = b.header.time;
        batch.push((Height(h), b));
    }

    let mat = confirm_wire_load_phase(&q, &params, ms, &batch, &ScriptPreverified::new())
        .expect("wire prep");
    assert_eq!(mat.batch.len(), 3);
    assert!(
        mat.batch.archive_plan.is_some(),
        "wire prep carries Class A plan for single commit era"
    );

    let ok = confirm_scripts_phase(mat.batch).expect("scripts");
    assert!(ok.batch.archive_plan.is_some());
    let fks = confirm_write_phase(&q, &params, ms, ok.batch).expect("commit");
    assert_eq!(fks.len(), 3);

    assert_eq!(q.tip_height(), Some(Height(4)));
    for (h, b) in &batch {
        assert!(
            q.is_block_archived(&b.block_hash().to_byte_array())
                .unwrap(),
            "h={} archived after unified commit",
            h.0
        );
    }
    pin_bq_wave_then_stamp_confirms_empty_block(&q, &params, ms, tip, tip_time);
}

/// Block size and weight come from the txstat rows Class A wrote. A zero
/// row falls back to rebuilding the block instead of shortening the sum.
fn pin_block_size_weight_from_txstat(q: &Query, b1: &Block) {
    use rbitcoin_store::TxStatRow;

    let hash = b1.block_hash().to_byte_array();
    let (hfk, _) = q.get_header_by_hash(&hash).unwrap().unwrap();
    let want = (b1.total_size() as u32, b1.weight().to_wu() as u32);
    let _ = q.sample_reset_reconstruct_archived();
    assert_eq!(q.block_size_weight(hfk).unwrap(), Some(want));
    assert_eq!(
        q.sample_reset_reconstruct_archived(),
        0,
        "the txstat sum does not reconstruct"
    );
    let cb_fk = q.header_tx_fks(hfk, Some(&hash)).unwrap().unwrap()[0];
    let row = q.get_txstat(cb_fk).unwrap().unwrap();
    let zero = TxStatRow {
        fee_sat: 0,
        base: 0,
        wit_extra: 0,
    };
    q.store().write_txstat_row(cb_fk, &zero).unwrap();
    assert_eq!(q.block_size_weight(hfk).unwrap(), Some(want));
    assert_eq!(q.sample_reset_reconstruct_archived(), 1);
    q.store().write_txstat_row(cb_fk, &row).unwrap();
    assert!(q.block_size_weight(Fk(99)).unwrap().is_none());
}

fn pin_confirm_refuses_without_advancing_tip(
    q: &Query,
    params: &ChainParams,
    ms: Milestone,
    b1: &Block,
) {
    use rbitcoin_consensus::{confirm_wire_load_phase, header_to_record, ScriptPreverified};
    use rbitcoin_query::ConfirmPrepared;

    let none = ScriptPreverified::new();
    let g = regtest_genesis();
    let non_contiguous = [(Height(1), g.clone()), (Height(3), g)];
    for batch in [&[][..], &non_contiguous[..]] {
        match confirm_wire_load_phase(q, params, ms, batch, &none) {
            Err(rbitcoin_consensus::ConsensusError::BadBlock(_)) => {}
            Err(e) => panic!("expected BadBlock, got {e}"),
            Ok(_) => panic!("load of {} blocks must refuse", batch.len()),
        }
    }

    let header_only = mine_regtest_block(b1.block_hash(), b1.header.time + 600, 2, vec![]);
    let (tip_fk, _) = q
        .get_header_by_hash(&b1.block_hash().to_byte_array())
        .unwrap()
        .unwrap();
    let rec = header_to_record(
        tip_fk,
        &header_only.header,
        header_only.block_hash().to_byte_array(),
    );
    let hfk = q.ensure_header(&rec).unwrap();
    let err = q
        .confirm_blocks_run(&[ConfirmPrepared {
            height: Height(2),
            header_fk: hfk,
            tx_fks: vec![],
        }])
        .expect_err("a header without a body cannot confirm");
    assert!(err.to_string().contains("header_txs"), "{err}");
    assert_eq!(q.tip_height(), Some(Height(1)));
    let genesis_cb = q.block_tx_fks(Height::GENESIS).unwrap()[0];
    assert_eq!(
        q.store().tx_height_get(genesis_cb).unwrap(),
        Some(0),
        "the height fence keeps its runs"
    );
}

/// A coinbase-only block taken off the block queue confirms through the
/// split lookup → load → scripts → write stages with no external head.
fn pin_bq_wave_then_stamp_confirms_empty_block(
    q: &Query,
    params: &ChainParams,
    ms: Milestone,
    tip: BlockHash,
    tip_time: u32,
) {
    use bitcoin::consensus::encode::serialize;
    use rbitcoin_consensus::{
        confirm_bq_resolve_wave_capped, confirm_scripts_phase, confirm_wire_load_from_plan,
        confirm_wire_lookup_stamp, confirm_write_phase, take_wave_items_for_load,
        ScriptPreverified, BQ_RESOLVE_WAVE_MAX_BLOCKS, BQ_RESOLVE_WAVE_MAX_INPUTS,
    };

    let h = q.tip_height().unwrap().0 + 1;
    let b = mine_regtest_block(tip, tip_time + 600, h, vec![]);
    q.block_queue_enqueue(
        h,
        b.block_hash().to_byte_array(),
        u64::from(h),
        &serialize(&b),
    )
    .unwrap();
    let wave = confirm_bq_resolve_wave_capped(
        q,
        params,
        ms,
        &[h],
        BQ_RESOLVE_WAVE_MAX_BLOCKS,
        BQ_RESOLVE_WAVE_MAX_INPUTS,
    )
    .unwrap();
    assert!(take_wave_items_for_load(q, &wave.items, q.lookup_taken_gen()).unwrap());
    assert!(!q.block_queue_has_height(h));
    let items = [(Height(h), std::sync::Arc::new(b), None)];
    let stamped = confirm_wire_lookup_stamp(q, params, ms, &items, None)
        .expect("a coinbase-only block needs no external head");
    let mat = confirm_wire_load_from_plan(q, params, ms, stamped, None, &ScriptPreverified::new())
        .expect("load");
    let ok = confirm_scripts_phase(mat.batch).expect("scripts");
    confirm_write_phase(q, params, ms, ok.batch).expect("write");
    assert_eq!(q.tip_height(), Some(Height(h)));
}

fn pin_wire_prep_ahead_cross_batch(
    q: &Query,
    params: &ChainParams,
    ms: Milestone,
    tip: BlockHash,
    tip_time: u32,
    cb: bitcoin::Txid,
    ha: u32,
) -> (BlockHash, u32) {
    use rbitcoin_consensus::{
        confirm_scripts_phase, confirm_wire_load_phase_pipelined, confirm_write_phase,
        ScriptPreverified, WireLoadPipeline,
    };

    let tip_h = q.tip_height();
    let spend_a = spend_anyone_can_spend(cb, 0, Amount::from_sat(49_0000_0000));
    let child_a = spend_anyone_can_spend(spend_a.compute_txid(), 0, Amount::from_sat(48_0000_0000));
    let ba = mine_regtest_block(tip, tip_time + 600, ha, vec![spend_a, child_a]);
    let a_out_txid = ba.txdata[2].compute_txid();
    let ha_hash = ba.block_hash();
    let hb = ha + 1;
    let spend_b = spend_anyone_can_spend(a_out_txid, 0, Amount::from_sat(47_0000_0000));
    let bb = mine_regtest_block(ha_hash, tip_time + 1200, hb, vec![spend_b]);

    let mut inflight = InFlight::new();
    let mut next_tx_start = q.tx_body_count().saturating_add(1).max(1);
    let mat_a = {
        let pipe = WireLoadPipeline {
            path_lo: ha,
            parent_hash: None,
            next_tx_start,
            in_flight: &inflight,
            skeleton: None,
            carried_need: Vec::new(),
            carried_header_fks: Vec::new(),
            carried_header_hashes: Vec::new(),
        };
        confirm_wire_load_phase_pipelined(
            q,
            params,
            ms,
            &[(Height(ha), ba.clone())],
            &ScriptPreverified::new(),
            Some(&pipe),
        )
        .expect("prep A")
    };
    assert_eq!(q.tip_height(), tip_h, "prep must not tip");

    let plan_a = mat_a.batch.archive_plan.as_ref().expect("plan A");
    assert!(
        plan_a.external_parents.is_empty(),
        "post-pin plan must not retain stamp staging on load→scripts→write handoff"
    );
    assert_eq!(plan_a.batch_pin.len(), plan_a.packed.len());
    for ((pin_p, _), pin_b) in plan_a.packed.iter().zip(plan_a.batch_pin.iter()) {
        assert!(
            std::sync::Arc::ptr_eq(pin_p, pin_b),
            "packed and batch_pin must share CreatePin"
        );
    }
    let cb_fk = q.tx_fk_by_txid_tip(cb.as_byte_array()).unwrap().unwrap();
    let spend_fk = plan_a.planned_fks[1];
    assert!(
        plan_a.packed[1].1.is_empty(),
        "wire plan must not retain scriptSig or witness"
    );
    assert_eq!(
        plan_a.edges[&spend_fk.0][0].create_fk, cb_fk,
        "a head-resolved parent is stamped by fk"
    );
    let edge = plan_a.edges[&spend_fk.0][0];
    assert_eq!(
        (edge.prev_txid, edge.vout, edge.spend_fk, edge.create_fk),
        (*cb.as_byte_array(), 0, spend_fk, cb_fk)
    );
    assert!(plan_a.edges[&plan_a.planned_fks[0].0][0]
        .create_fk
        .is_null());
    let same_batch: Vec<_> = plan_a
        .same_batch_spent_overlay()
        .into_iter()
        .flatten()
        .collect();
    assert_eq!(
        same_batch,
        [(0, plan_a.planned_fks[2], 0)],
        "the in-block child spends the spend's output in this batch"
    );
    if plan_a.batch_pin.len() == plan_a.planned_fks.len() {
        inflight.note_pins(
            plan_a
                .planned_fks
                .iter()
                .zip(plan_a.batch_pin.iter())
                .map(|(fk, pin)| (*fk, pin)),
            None,
        );
    } else {
        inflight.note_pins(
            plan_a
                .packed
                .iter()
                .zip(plan_a.planned_fks.iter())
                .map(|((pin, _), fk)| (*fk, pin)),
            None,
        );
    }
    if let Some(last) = plan_a.planned_fks.last().and_then(|f| f.get()) {
        next_tx_start = last.saturating_add(1).max(1);
    }

    let mat_b = {
        let pipe = WireLoadPipeline {
            path_lo: hb,
            parent_hash: Some(ha_hash.to_byte_array()),
            next_tx_start,
            in_flight: &inflight,
            skeleton: None,
            carried_need: Vec::new(),
            carried_header_fks: Vec::new(),
            carried_header_hashes: Vec::new(),
        };
        confirm_wire_load_phase_pipelined(
            q,
            params,
            ms,
            &[(Height(hb), bb.clone())],
            &ScriptPreverified::new(),
            Some(&pipe),
        )
        .expect("prep B while parent batch still uncommitted")
    };
    assert_eq!(q.tip_height(), tip_h);

    let ok_a = confirm_scripts_phase(mat_a.batch).expect("scripts A");
    confirm_write_phase(q, params, ms, ok_a.batch).expect("write A");
    assert_eq!(q.tip_height(), Some(Height(ha)));
    assert_eq!(q.block_tx_fks(Height(ha)).unwrap()[1], spend_fk);
    let (off, _) = q.store().tx_spent_range(cb_fk).unwrap();
    let meta = q
        .store()
        .get_spender_meta_at_abs_batch(&[rbitcoin_store::spent_abs(off, 0)])
        .unwrap();
    assert_eq!(
        meta[0].unwrap().0,
        spend_fk,
        "write annotates the spent slot"
    );

    let ok_b = confirm_scripts_phase(mat_b.batch).expect("scripts B");
    confirm_write_phase(q, params, ms, ok_b.batch).unwrap_or_else(|e| {
        panic!("write B after load-ahead must fill parent denserels from committed A (got {e})");
    });
    assert_eq!(q.tip_height(), Some(Height(hb)));
    (bb.block_hash(), bb.header.time)
}

fn pin_wire_prep_already_archived(
    q: &Query,
    params: &ChainParams,
    ms: Milestone,
    tip: BlockHash,
    tip_time: u32,
    cb: bitcoin::Txid,
    ha: u32,
) -> (BlockHash, u32) {
    use rbitcoin_consensus::{
        commit_class_a_run, confirm_scripts_phase, confirm_wire_load_phase, confirm_write_phase,
        ScriptPreverified,
    };

    let tip_before = q.tip_height();
    let spend_a = spend_anyone_can_spend(cb, 0, Amount::from_sat(49_0000_0000));
    let ba = mine_regtest_block(tip, tip_time + 600, ha, vec![spend_a]);
    let a_out = ba.txdata[1].compute_txid();
    let hb = ha + 1;
    let spend_b = spend_anyone_can_spend(a_out, 0, Amount::from_sat(48_0000_0000));
    let bb = mine_regtest_block(ba.block_hash(), ba.header.time + 600, hb, vec![spend_b]);
    commit_class_a_run(
        q,
        params,
        &[(Height(ha), ba.clone()), (Height(hb), bb.clone())],
        ms,
    )
    .unwrap();
    assert_eq!(q.tip_height(), tip_before);

    let batch = [(Height(ha), ba), (Height(hb), bb.clone())];
    let mat = confirm_wire_load_phase(q, params, ms, &batch, &ScriptPreverified::new())
        .expect("wire prep already-archived");
    assert!(
        mat.batch.archive_plan.is_none()
            || mat
                .batch
                .archive_plan
                .as_ref()
                .is_some_and(|p| p.is_empty()),
        "bodies already archived → no Class A plan (or empty)"
    );
    let ok = confirm_scripts_phase(mat.batch).expect("scripts");
    confirm_write_phase(q, params, ms, ok.batch).unwrap_or_else(|e| {
        panic!(
            "write of already-archived wire batch must fill denserels for same-batch creates (got {e})"
        );
    });
    assert_eq!(q.tip_height(), Some(Height(hb)));
    (bb.block_hash(), bb.header.time)
}

fn pin_wire_prep_cold_class_a_denserels(
    q: &Query,
    params: &ChainParams,
    ms: Milestone,
    tip: BlockHash,
    tip_time: u32,
    cb: bitcoin::Txid,
    h_split: u32,
) {
    use rbitcoin_consensus::{
        confirm_scripts_phase, confirm_wire_load_phase, confirm_write_phase, ScriptPreverified,
    };
    use rbitcoin_test::mine::split_anyone_can_spend;

    let split = split_anyone_can_spend(
        cb,
        0,
        &[
            Amount::from_sat(25_0000_0000),
            Amount::from_sat(24_0000_0000),
        ],
    );
    let b_split = mine_regtest_block(tip, tip_time + 600, h_split, vec![split]);
    let parent_txid = b_split.txdata[1].compute_txid();
    rbitcoin_consensus::confirm_wire_run(q, params, ms, &[(Height(h_split), b_split.clone())])
        .unwrap();
    assert!(
        q.store()
            .get_fk_by_txid(parent_txid.as_byte_array())
            .unwrap()
            .is_some(),
        "parent head"
    );

    let h_a = h_split + 1;
    let spend_a = spend_anyone_can_spend(parent_txid, 0, Amount::from_sat(24_0000_0000));
    let ba = mine_regtest_block(
        b_split.block_hash(),
        b_split.header.time + 600,
        h_a,
        vec![spend_a],
    );
    let h_b = h_split + 2;
    let spend_b = spend_anyone_can_spend(parent_txid, 1, Amount::from_sat(23_0000_0000));
    let bb = mine_regtest_block(
        ba.block_hash(),
        b_split.header.time + 1200,
        h_b,
        vec![spend_b],
    );

    let mat_a = confirm_wire_load_phase(
        q,
        params,
        ms,
        &[(Height(h_a), ba)],
        &ScriptPreverified::new(),
    )
    .expect("prep A");
    let ok_a = confirm_scripts_phase(mat_a.batch).expect("scripts A");
    confirm_write_phase(q, params, ms, ok_a.batch).expect("write A");

    let mat_b = confirm_wire_load_phase(
        q,
        params,
        ms,
        &[(Height(h_b), bb)],
        &ScriptPreverified::new(),
    )
    .expect("prep B");
    let ok_b = confirm_scripts_phase(mat_b.batch).expect("scripts B");
    confirm_write_phase(q, params, ms, ok_b.batch).expect("write B");
    assert_eq!(q.tip_height(), Some(Height(h_b)));
}

/// One mature pad: load-ahead parent fill, already-archived plan=None annotate,
/// and cold Class A denserels for sequential spends of one create.
#[test]
fn wire_prep_parent_layout_and_load_ahead() {
    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create_tiny(td.store_path()).unwrap();
    q.enter_direct_index_mode().unwrap();
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;
    let maturity = params.coinbase_maturity();

    let genesis = regtest_genesis();
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;

    let b1 = mine_regtest_block(tip, tip_time + 600, 1, vec![]);
    let cb1 = b1.txdata[0].compute_txid();
    accept_and_connect_block(&q, &params, Height(1), &b1, ms).unwrap();
    tip = b1.block_hash();
    tip_time = b1.header.time;
    (tip, tip_time) = pad_empty_from(&q, &params, tip, tip_time, 2, maturity);
    assert_eq!(q.tip_height(), Some(Height(maturity)));
    let cb2 = q.reconstruct_block_at_height(Height(2)).unwrap().txdata[0].compute_txid();
    let cb3 = q.reconstruct_block_at_height(Height(3)).unwrap().txdata[0].compute_txid();

    (tip, tip_time) =
        pin_wire_prep_ahead_cross_batch(&q, &params, ms, tip, tip_time, cb1, maturity + 1);
    (tip, tip_time) =
        pin_wire_prep_already_archived(&q, &params, ms, tip, tip_time, cb2, maturity + 3);
    pin_wire_prep_cold_class_a_denserels(&q, &params, ms, tip, tip_time, cb3, maturity + 5);
}
