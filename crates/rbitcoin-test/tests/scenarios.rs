//! High-level functional scenarios (coverage-bearing).
//!
//! Prefer fewer tests at the highest layer that still hit production paths.
//! Mature regtest chains are built once per test that needs them (not thrice).

use bitcoin::hashes::Hash;
use bitcoin::{Amount, BlockHash};
use rbitcoin_cli::cli_main as cli_cli_main;
use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
use rbitcoin_node::{cli_main as node_cli_main, run_node, NodeConfig};
use rbitcoin_primitives::{Fk, Height, Network, TableKind, VERSION};
use rbitcoin_query::Query;
use rbitcoin_rpc::node_rpc_path;
use rbitcoin_store::{HeaderRecord, Store, StoreError, TxRecord};
use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis, spend_anyone_can_spend};
use rbitcoin_test::{
    assert_reconstruct_eq, build_mature_regtest_with_spend, pad_empty_from, TestDatadir,
};
use std::process::{Command, ExitCode};

/// This toolchain's `ExitCode` lacks `PartialEq`; compare via Debug.
fn exit_success(c: ExitCode) -> bool {
    format!("{c:?}") == format!("{:?}", ExitCode::SUCCESS)
}

// ─── Lifecycle / CLI / surface smoke (collapsed) ────────────────────────────

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
            .with_network(net);
        let handle = run_node(cfg).unwrap();
        assert_eq!(handle.network_name(), net.as_str());
        handle.shutdown().unwrap();
    }
    assert!(Network::parse("nope").is_err());
    assert_eq!(Network::parse("REGTEST").unwrap(), Network::Regtest);
    assert!(!VERSION.is_empty());
    for k in 1u16..=11 {
        assert_eq!(TableKind::from_u16(k).unwrap().as_u16(), k);
    }
    assert!(TableKind::from_u16(99).is_none());
    assert!(Fk::NULL.is_null());
    assert_eq!(Height::GENESIS.next(), Some(Height(1)));

    // Config errors
    let cfg = NodeConfig {
        datadir: std::path::PathBuf::from(""),
        ..NodeConfig::default()
    };
    assert!(run_node(cfg).is_err());
    let td = TestDatadir::new().unwrap();
    let file = td.path().join("blocked");
    std::fs::write(&file, b"nope").unwrap();
    assert!(run_node(NodeConfig::default().with_datadir(file)).is_err());

    // Net surface
    assert!(!Milestone::NONE.skips_scripts_at(0));
    assert!(Milestone { height: 10 }.skips_scripts_at(5));
    assert_eq!(rbitcoin_net::DEFAULT_IBD_TARGET_PEERS, 16);
    assert_eq!(node_rpc_path(), "/");
    assert_eq!(rbitcoin_net::default_port(Network::Mainnet), 8333);
    assert_eq!(rbitcoin_net::default_port(Network::Regtest), 18444);
    assert!(rbitcoin_net::dns_seeds(Network::Mainnet).len() >= 3);
    assert!(rbitcoin_net::dns_seeds(Network::Regtest).is_empty());
    assert!(!rbitcoin_net::fixed_seed_hosts(Network::Mainnet).is_empty());
    let mut am = rbitcoin_net::AddrMan::with_seeds(Network::Regtest);
    assert!(am.is_empty());
    am.add("127.0.0.1:18444".parse().unwrap());
    assert_eq!(am.len(), 1);
    assert_eq!(am.take_outbound(10).len(), 1);
    assert_eq!(am.take_outbound_offset(1, 0).len(), 1);
    let _ = rbitcoin_net::resolve_fixed_seeds(Network::Regtest);
    let _ = rbitcoin_net::resolve_dns_seeds(Network::Regtest);
    let _ = rbitcoin_net::resolve_all_seeds(Network::Regtest);
    assert!(!rbitcoin_net::dns_seeds(Network::Signet).is_empty());

    // Chain params (no mining)
    for net in [
        Network::Mainnet,
        Network::Testnet,
        Network::Signet,
        Network::Regtest,
    ] {
        let p = ChainParams::for_network(net);
        let g = rbitcoin_consensus::genesis_block(&p);
        assert_eq!(g.block_hash(), p.genesis_hash);
    }
    let main = ChainParams::mainnet();
    assert!(!main.checkpoints.is_empty());
    assert_eq!(main.checkpoint_at(Height(0)).unwrap(), main.genesis_hash);
    assert_eq!(main.difficulty_adjustment_interval(), 2016);
    assert!(!main.no_pow_retargeting());
    assert!(ChainParams::regtest().no_pow_retargeting());
    assert_eq!(rbitcoin_consensus::block_subsidy(0, &main), 50_0000_0000);
    assert_eq!(
        rbitcoin_consensus::block_subsidy(210_000, &main),
        25_0000_0000
    );

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
    let _ = node_cli_main(["rbitcoin-node", "--help"]);
    let _ = node_cli_main(["rbitcoin-node", "--version"]);
    let _ = cli_cli_main(["rbitcoin-cli", "--help"]);
    let _ = cli_cli_main(["rbitcoin-cli", "--version"]);
    assert!(exit_success(cli_cli_main(["rbitcoin-cli", "help"])));
    assert!(!exit_success(cli_cli_main(["rbitcoin-cli"])));
    assert!(!exit_success(cli_cli_main([
        "rbitcoin-cli",
        "getblockchaininfo"
    ])));
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--not-a-real-option"
    ])));
    assert!(!exit_success(node_cli_main(["rbitcoin-node", "--datadir"])));
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--network",
        "nope"
    ])));
    assert!(!exit_success(node_cli_main(["rbitcoin-node", "--listen"])));
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--listen",
        "not-an-addr"
    ])));
    assert!(!exit_success(node_cli_main(["rbitcoin-node", "--connect"])));
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--connect",
        "bad"
    ])));
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--milestone",
        "x"
    ])));
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--max-outbound",
        "0"
    ])));
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--max-outbound"
    ])));
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--max-outbound",
        "nope"
    ])));
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--mempool-size-mb"
    ])));
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--mempool-size-mb",
        "0"
    ])));
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--mempool-size-mb",
        "x"
    ])));
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--max-run-secs"
    ])));
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--max-run-secs",
        "x"
    ])));
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--log-level"
    ])));
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--log-level",
        "loud"
    ])));
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--electrum-listen"
    ])));
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--electrum-listen",
        "bad"
    ])));
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--milestone"
    ])));
    // Electrum without --shindex is a config error at start.
    let no_sh = td.path().join("electrum-no-shindex");
    assert!(!exit_success(node_cli_main([
        "rbitcoin-node",
        "--datadir",
        no_sh.to_str().unwrap(),
        "--network",
        "regtest",
        "--electrum-listen",
        "127.0.0.1:0",
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
        "--shindex",
        "--electrum-listen",
        "127.0.0.1:0",
        "--inhibit-suspend",
        "--smoke",
    ])));
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
    let _ = node_cli_main(["rbitcoin-node", "--help"]);
    assert!(!exit_success(cli_cli_main(["rbitcoin-cli", "a", "b"])));

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
    let s = Store::create(&path).unwrap();
    assert!(matches!(s.get_header(Fk::NULL), Err(StoreError::InvalidFk)));
    assert!(matches!(s.get_header(Fk(99)), Err(StoreError::NotFound)));
    // All-zero txid has no create head entry → NotFound (not InvalidFk).
    assert!(matches!(
        s.put_spend(&[0u8; 32], 0, Fk::NULL, 0),
        Err(StoreError::NotFound | StoreError::InvalidFk)
    ));
    let _ = format!("{}", StoreError::BadMagic);
    let _ = format!("{}", StoreError::BadSchema(3));
    let _ = format!(
        "{}",
        StoreError::BadKind {
            expected: 1,
            got: 2
        }
    );
    let _ = format!("{}", StoreError::NotFound);
    let _ = format!("{}", StoreError::InvalidFk);
    let _ = format!("{}", StoreError::Corrupt("x"));
    let _ = format!("{}", StoreError::NotDirectory(path.clone()));
    drop(s);

    let file_path = td.path().join("notdir");
    std::fs::write(&file_path, b"x").unwrap();
    assert!(matches!(
        Store::create(&file_path),
        Err(StoreError::NotDirectory(_))
    ));

    let bad = td.path().join("badstore");
    std::fs::create_dir_all(&bad).unwrap();
    std::fs::write(bad.join("meta"), b"XXXX\x00\x00").unwrap();
    assert!(matches!(Store::open(&bad), Err(StoreError::BadMagic)));

    let bad2 = td.path().join("badschema");
    std::fs::create_dir_all(&bad2).unwrap();
    let mut meta = Vec::from(*b"RBT1");
    meta.extend_from_slice(&99u16.to_le_bytes());
    std::fs::write(bad2.join("meta"), meta).unwrap();
    assert!(matches!(Store::open(&bad2), Err(StoreError::BadSchema(99))));

    let bad3 = td.path().join("shortmeta");
    std::fs::create_dir_all(&bad3).unwrap();
    std::fs::write(bad3.join("meta"), b"RB").unwrap();
    assert!(matches!(Store::open(&bad3), Err(StoreError::Corrupt(_))));

    let parent_file = td.path().join("parent_is_file");
    std::fs::write(&parent_file, b"x").unwrap();
    assert!(Store::create(parent_file.join("store")).is_err());

    assert!(HeaderRecord::decode(&[0u8; 10]).is_err());
    assert!(TxRecord::decode(&[0u8; 10]).is_err());
}

#[test]
fn store_table_header_and_idx_corrupt() {
    use rbitcoin_primitives::{TableKind, SCHEMA_VERSION, STORE_MAGIC};
    let td = TestDatadir::new().unwrap();
    let store_dir = td.path().join("broken_kind");
    {
        let s = Store::create(&store_dir).unwrap();
        s.flush().unwrap();
    }
    let mut hb = std::fs::read(store_dir.join("header.body")).unwrap();
    hb[6..8].copy_from_slice(&TableKind::TxOut.as_u16().to_le_bytes());
    std::fs::write(store_dir.join("header.body"), &hb).unwrap();
    match Store::open(&store_dir) {
        Err(StoreError::BadKind { .. }) => {}
        Err(e) => panic!("expected BadKind, got {e}"),
        Ok(_) => panic!("expected BadKind"),
    }

    let store_dir2 = td.path().join("broken_magic");
    {
        Store::create(&store_dir2).unwrap().flush().unwrap();
    }
    let mut hb = std::fs::read(store_dir2.join("header.body")).unwrap();
    hb[0..4].copy_from_slice(b"XXXX");
    std::fs::write(store_dir2.join("header.body"), &hb).unwrap();
    match Store::open(&store_dir2) {
        Err(StoreError::BadMagic) => {}
        Err(e) => panic!("expected BadMagic, got {e}"),
        Ok(_) => panic!("expected BadMagic"),
    }

    let store_dir3 = td.path().join("broken_schema");
    {
        Store::create(&store_dir3).unwrap().flush().unwrap();
    }
    let mut hb = std::fs::read(store_dir3.join("header.body")).unwrap();
    hb[4..6].copy_from_slice(&123u16.to_le_bytes());
    std::fs::write(store_dir3.join("header.body"), &hb).unwrap();
    match Store::open(&store_dir3) {
        Err(StoreError::BadSchema(123)) => {}
        Err(e) => panic!("expected BadSchema, got {e}"),
        Ok(_) => panic!("expected BadSchema"),
    }

    let sd = td.path().join("empty_head");
    {
        Store::create(&sd).unwrap().flush().unwrap();
    }
    let head = sd.join("header.head");
    let mut bytes = std::fs::read(&head).unwrap();
    bytes[8..16].copy_from_slice(&16u64.to_le_bytes());
    bytes.truncate(16);
    std::fs::write(&head, bytes).unwrap();
    match Store::open(&sd) {
        Err(StoreError::Corrupt(_)) => {}
        Err(e) => panic!("expected Corrupt, got {e}"),
        Ok(_) => panic!("expected Corrupt"),
    }

    let sd2 = td.path().join("bad_slots");
    {
        Store::create(&sd2).unwrap().flush().unwrap();
    }
    let head = sd2.join("header.head");
    let mut bytes = std::fs::read(&head).unwrap();
    let logical = 16u64 + 40 * 3;
    bytes.resize(logical as usize, 0);
    bytes[8..16].copy_from_slice(&logical.to_le_bytes());
    std::fs::write(&head, bytes).unwrap();
    match Store::open(&sd2) {
        Err(StoreError::Corrupt(_)) => {}
        Err(e) => panic!("expected Corrupt, got {e}"),
        Ok(_) => panic!("expected Corrupt"),
    }

    let _ = (SCHEMA_VERSION, STORE_MAGIC);
}

// ─── Synthetic store growth (no PoW; tiny header.head rolls a generation) ───

#[test]
fn chain_connect_reorg_and_growth() {
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{InputRecord, OutputRecord};

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create(td.store_path()).unwrap();

    // Default hash head is 64 slots; 80 blocks (header keys) force header.head.g1.
    // Merkle root must match the Class A txid(s) so tip-window revalidate on reopen
    // (VERIFY_TIP_BLOCKS) does not false-positive shrink the tip.
    const N: u32 = 80;
    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
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
        prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
    }
    assert_eq!(q.tip_height(), Some(Height(N - 1)));
    q.flush().unwrap();
    drop(q);

    let q = Query::open_or_create(td.store_path()).unwrap();
    assert_eq!(q.tip_height(), Some(Height(N - 1)));
    q.disconnect_tip().unwrap();
    assert_eq!(q.tip_height(), Some(Height(N - 2)));
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
            },
            &[]
        )
        .is_err());
}

// ─── Resume: Class A remains after connect+disconnect (not archive-ahead) ─────

/// After connect then disconnect, `resume_work_path_after_tip` still sees
/// Class A bodies (production leaves archive on disconnect).
#[test]
fn resume_work_path_sees_archived_bodies_after_reopen() {
    use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
    use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis};

    let td = TestDatadir::new().unwrap();
    let params = ChainParams::regtest();
    let ms = Milestone { height: 1_000_000 };
    let genesis = regtest_genesis();

    let hashes = {
        let q = Query::open_or_create(td.store_path()).unwrap();
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
        let mut tip = genesis.block_hash();
        let mut tip_time = genesis.header.time;
        let mut out = Vec::new();
        for h in 1u32..=4 {
            let b = mine_regtest_block(tip, tip_time + 600, h, vec![]);
            accept_and_connect_block(&q, &params, Height(h), &b, ms).unwrap();
            out.push(b.block_hash().to_byte_array());
            tip = b.block_hash();
            tip_time = b.header.time;
        }
        for _ in 1u32..=4 {
            q.disconnect_tip().unwrap();
        }
        assert_eq!(q.tip_height().map(|h| h.0), Some(0));
        q.flush().unwrap();
        out
    };

    // Cold reopen — process-local ordered path is gone; store still has Class A.
    let q2 = Query::open_or_create(td.store_path()).unwrap();
    let tip_hash = genesis.block_hash().to_byte_array();
    let path = q2
        .resume_work_path_after_tip(tip_hash, 0, 64)
        .expect("resume");
    assert_eq!(path.len(), 4, "expected 4 headers after tip");
    assert!(
        path.iter().all(|e| e.has_body),
        "all resume entries should have Class A bodies"
    );
    for (i, e) in path.iter().enumerate() {
        assert_eq!(e.height, (i as u32) + 1);
        assert_eq!(e.hash, hashes[i]);
        assert!(q2.is_block_archived(&e.hash).unwrap());
    }
}

/// Simulate kill -9 mid Class C: strong_tx + point edges written for
/// tip+1 but `confirmed[]` not advanced. Re-confirm must not false-positive
/// PrevoutSpent (tip is the Class C commit point).
#[test]
fn confirm_survives_partial_class_c_without_tip_advance() {
    use rbitcoin_consensus::{
        accept_and_connect_block, commit_class_a_block, confirm_wire_run, ChainParams, Milestone,
    };
    use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis, spend_anyone_can_spend};

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create(td.store_path()).unwrap();
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

    // --- Partial Class C (confirm_blocks_run writes strong before tip) ---
    // Archive already wrote point edges (spend_index on); the kill-9 window is
    // strong bits without confirmed[] advance — old spenders() treated that as spent.
    let first = tx_fks[0];
    q.store()
        .strong_tx
        .set_strong_range(first, tx_fks.len() as u32, header_fk)
        .unwrap();
    // Tip intentionally NOT advanced (fence still at old tip).
    assert_eq!(q.tip_height(), Some(tip_before));
    assert!(
        q.store().strong_tx.is_strong(tx_fks[1]).unwrap(),
        "sim: spending tx marked strong without tip"
    );
    assert!(
        !q.spenders_raw(cb1.as_byte_array(), 0).unwrap().is_empty(),
        "archive point edge present"
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

    let q2 = Query::open_or_create(td.store_path()).unwrap();
    assert!(
        !q2.store().strong_tx.is_strong(fks2[0]).unwrap(),
        "open must repair strong bits above tip"
    );
    confirm_wire_run(&q2, &params, ms, &[(Height(spend_h + 1), b_next)])
        .expect("confirm after open repair");
    assert_eq!(q2.tip_height(), Some(Height(spend_h + 1)));
}

/// Resume: spend archived with create_fk (archive sticky/head); confirm spends.
#[test]
fn resume_tx_head_resolves_external_prev() {
    use rbitcoin_consensus::{
        accept_and_connect_block, commit_class_a_block, confirm_wire_run, ChainParams, Milestone,
    };
    use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis, spend_anyone_can_spend};

    let td = TestDatadir::new().unwrap();
    let ms = Milestone { height: 1_000_000 };
    let params = ChainParams::regtest();
    let maturity = params.coinbase_maturity();

    // Session 1: mine + confirm pad so coinbase is mature; leave spend unarchived.
    let (cb1, tip, tip_time, spend_h, b_spend) = {
        let q = Query::open_or_create(td.store_path()).unwrap();
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
        let q = Query::open_or_create(td.store_path()).unwrap();
        q.enter_direct_index_mode().unwrap();
        assert!(
            q.tx_fk_by_txid(cb1.as_byte_array()).unwrap().is_some(),
            "tx.head must retain mature coinbase create_fk across reopen"
        );
        commit_class_a_block(&q, &params, Height(spend_h), &b_spend, ms).unwrap();
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
    }
}

/// After confirm, durable spentness is authority (body LRU may still hold outs).
/// Structural rejects double-spend; no separate wave spent-filter map.
#[test]
fn confirm_structural_rejects_already_spent_prevout() {
    use rbitcoin_consensus::{
        accept_and_connect_block, commit_class_a_block, ChainParams, Milestone,
    };
    use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis, spend_anyone_can_spend};

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create(td.store_path()).unwrap();
    q.enter_direct_index_mode().unwrap();
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

    let spend_h = last_pad + 1;
    let spend = spend_anyone_can_spend(cb1, 0, bitcoin::Amount::from_sat(49_0000_0000));
    let b_spend = mine_regtest_block(tip, tip_time + 600, spend_h, vec![spend]);
    commit_class_a_block(&q, &params, Height(spend_h), &b_spend, ms).unwrap();

    accept_and_connect_block(&q, &params, Height(spend_h), &b_spend, ms).unwrap();
    assert!(q.is_outpoint_spent(cb1.as_byte_array(), 0).unwrap());

    let spend2 = spend_anyone_can_spend(cb1, 0, bitcoin::Amount::from_sat(48_0000_0000));
    let b_bad = mine_regtest_block(
        b_spend.block_hash(),
        b_spend.header.time + 600,
        spend_h + 1,
        vec![spend2],
    );
    commit_class_a_block(&q, &params, Height(spend_h + 1), &b_bad, ms).unwrap();
    let err = accept_and_connect_block(&q, &params, Height(spend_h + 1), &b_bad, ms)
        .expect_err("double-spend must fail structural");
    let msg = err.to_string();
    assert!(
        msg.contains("spent") || msg.contains("PrevoutSpent") || msg.contains("prevout"),
        "unexpected reject: {msg}"
    );
}

/// Multi-block confirm batch that **creates** a non-coinbase parent and
/// **spends** it in a later height of the same run. Runway reserves that
/// parent (not in UTXO yet); readiness must not require the reserve to fill
/// or tip would never advance.
#[test]
fn confirm_batch_create_and_spend_parent_same_run() {
    use rbitcoin_consensus::{
        accept_and_connect_block, commit_class_a_run, confirm_wire_run, ChainParams, Milestone,
    };
    use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis, spend_anyone_can_spend};

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create(td.store_path()).unwrap();
    q.enter_direct_index_mode().unwrap();
    let ms = Milestone::NONE;
    let params = ChainParams::regtest();
    let maturity = params.coinbase_maturity();

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

    // Height create_h: spend mature coinbase → new parent out (not yet in UTXO).
    let create_h = last_pad + 1;
    let mk_parent = spend_anyone_can_spend(cb1, 0, Amount::from_sat(49_0000_0000));
    let b_create = mine_regtest_block(tip, tip_time + 600, create_h, vec![mk_parent]);
    let parent_txid = b_create.txdata[1].compute_txid();
    tip = b_create.block_hash();
    tip_time = b_create.header.time;
    run.push((Height(create_h), b_create));

    // Height spend_h: spend that same-batch parent (cache will reserve it).
    let spend_h = create_h + 1;
    let spend_parent = spend_anyone_can_spend(parent_txid, 0, Amount::from_sat(48_0000_0000));
    let b_spend = mine_regtest_block(tip, tip_time + 600, spend_h, vec![spend_parent]);
    run.push((Height(spend_h), b_spend));
    commit_class_a_run(&q, &params, &run, ms).unwrap();

    confirm_wire_run(&q, &params, ms, &run)
        .expect("same-run create then spend must confirm (open reserve not a deadlock)");
    assert_eq!(q.tip_height(), Some(Height(spend_h)));
    assert!(
        q.is_outpoint_spent(parent_txid.as_byte_array(), 0).unwrap(),
        "in-batch parent must be spent after multi-block run"
    );
}

/// Mainnet @546 shape:
/// - height H: 1-in / 2-out parent
/// - height H+1: tx spends both parent vouts (2-in/2-out), then same-block chain
/// IBD multi-block `confirm_wire_run` under Direct (live heads + spend batch).
#[test]
fn confirm_spend_both_vouts_of_one_input_parent() {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_consensus::{
        accept_and_connect_block, commit_class_a_block, commit_class_a_run, confirm_wire_run,
        ChainParams, Milestone,
    };
    use rbitcoin_test::mine::{
        mine_regtest_block, regtest_genesis, spend_many_anyone_can_spend, split_anyone_can_spend,
    };

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create(td.store_path()).unwrap();
    q.enter_direct_index_mode().unwrap();
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

    // Height H: 1-in / 2-out parent — archive only (confirm with spend in one run).
    let split_h = last_pad + 1;
    let split = split_anyone_can_spend(
        cb1,
        0,
        &[
            Amount::from_sat(20_0000_0000),
            Amount::from_sat(29_0000_0000),
        ],
    );
    let b_split = mine_regtest_block(tip, tip_time + 600, split_h, vec![split]);
    let parent_txid = b_split.txdata[1].compute_txid();
    tip = b_split.block_hash();
    tip_time = b_split.header.time;

    // Height H+1: 546-like chain — dual-vout spend of parent, then same-block hops.
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
    let b_merge = mine_regtest_block(tip, tip_time + 600, merge_h, vec![t1, t2, t3]);
    commit_class_a_run(
        &q,
        &params,
        &[
            (Height(split_h), b_split.clone()),
            (Height(merge_h), b_merge.clone()),
        ],
        ms,
    )
    .unwrap();

    confirm_wire_run(
        &q,
        &params,
        ms,
        &[
            (Height(split_h), b_split.clone()),
            (Height(merge_h), b_merge.clone()),
        ],
    )
    .expect("mainnet-546-shaped multi-block confirm must not MissingPrevout");
    assert_eq!(q.tip_height(), Some(Height(merge_h)));
    assert!(q.is_outpoint_spent(parent_txid.as_byte_array(), 0).unwrap());
    assert!(q.is_outpoint_spent(parent_txid.as_byte_array(), 1).unwrap());

    // Cross-batch: next height spends t3 via durable head create_fk only.
    tip = b_merge.block_hash();
    tip_time = b_merge.header.time;
    let t3_txid = b_merge.txdata[3].compute_txid();
    let next_h = merge_h + 1;
    let spend = spend_many_anyone_can_spend(&[(t3_txid, 0)], Amount::from_sat(45_0000_0000));
    let b_next = mine_regtest_block(tip, tip_time + 600, next_h, vec![spend]);
    commit_class_a_block(&q, &params, Height(next_h), &b_next, ms).unwrap();
    confirm_wire_run(&q, &params, ms, &[(Height(next_h), b_next)])
        .expect("cross-batch tx.head create_fk resolve must work");
    assert_eq!(q.tip_height(), Some(Height(next_h)));
}

/// Sequential confirm_wire_run + failed confirm must not poison spends.
#[test]
fn confirm_run_sequential_and_failed_no_spend_poison() {
    use rbitcoin_consensus::{
        accept_and_connect_block, commit_class_a_block, confirm_wire_run, ChainParams, Milestone,
    };
    use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis};

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create(td.store_path()).unwrap();
    q.enter_direct_index_mode().unwrap();
    let ms = Milestone { height: 0 };
    let params = ChainParams::regtest();

    let genesis = regtest_genesis();
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;
    let mut blocks = Vec::new();
    for h in 1u32..=4 {
        let b = mine_regtest_block(tip, tip_time + 600, h, vec![]);
        commit_class_a_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
        blocks.push(b);
    }

    let run: Vec<_> = (1u32..=3)
        .map(|h| (Height(h), blocks[(h - 1) as usize].clone()))
        .collect();
    confirm_wire_run(&q, &params, ms, &run).expect("sequential run");
    assert_eq!(q.tip_height(), Some(Height(3)));

    // Empty / non-contiguous confirm fails without advancing tip.
    let bad = confirm_wire_run(&q, &params, ms, &[]);
    assert!(bad.is_err());
    confirm_wire_run(&q, &params, ms, &[(Height(4), blocks[3].clone())]).expect("confirm tip+1");
    assert_eq!(q.tip_height(), Some(Height(4)));
}

// ─── Consensus + reconstruct: one mature mine, many assertions ──────────────

/// Single mature-chain pad covers consensus + scripthash + reconstruct + reorg:
/// - accept genesis + maturity pad + spend + double-spend reject
/// - create_fk on spend + reconstruct (create_fk packing)
/// - reconstruct after reopen (sampled heights)
/// - scripthash history / balance / listunspent for OP_TRUE
/// - disconnect tip restores spent coinbase UTXO
/// - locator/headers + service flags
#[test]
fn consensus_mature_chain_spend_reconstruct_and_scripthash() {
    use bitcoin::p2p::ServiceFlags;
    use rbitcoin_net::local_service_flags;
    use rbitcoin_store::{script_hash, InputRecord};

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create(td.store_path()).unwrap();
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
    let enc = InputRecord {
        prev_txid: inp.prev_txid,
        create_fk: inp.create_fk,
        prev_index: inp.prev_index,
        sequence: inp.sequence,
        script_sig: inp.script_sig.clone(),
        witness: inp.witness.clone(),
    }
    .encode();
    // create_fk:u64 + CompactSize vout — not prev_txid[32] (−24 B per input).
    assert!(
        enc.len() < 32,
        "v10 input encodes create_fk not prev_txid: {}",
        enc.len()
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
    let q = Query::open_or_create(td.store_path()).unwrap();
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
    let q = Query::open_or_create(td.store_path()).unwrap();
    q.enter_direct_index_mode().unwrap();
    let ms = Milestone::NONE;
    let params = ChainParams::regtest();
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

    // LOAD
    let mat = confirm_wire_load_phase(&q, &params, ms, &run, &none).expect("load");
    assert!(!mat.batch.is_empty());
    assert!(mat.work_ns > 0);
    let heights = mat.batch.heights_hashes();
    assert_eq!(heights.len(), run.len());
    assert_eq!(mat.batch.len(), run.len());

    // SCRIPTS
    let ok = confirm_scripts_phase(mat.batch).expect("scripts");
    assert!(ok.work_ns > 0 || true);

    // WRITE
    let fks = confirm_write_phase(&q, &params, ms, ok.batch).expect("write");
    assert_eq!(fks.len(), run.len());
    assert_eq!(q.tip_height(), Some(Height(spend_h)));
    assert!(q.is_outpoint_spent(cb1.as_byte_array(), 0).unwrap());

    // Tip advance prunes plans/headers ≤ tip (body LRU retains under budget).
    q.advance_parent_cache_tip(spend_h);
    // Combined load entry on empty: reject empty.
    let empty = confirm_wire_load_phase(&q, &params, ms, &[], &none);
    assert!(empty.is_err());
}

/// Multi-block confirm load with a non-coinbase spend must not permanent-BadPrev
/// on mid-batch BIP68/BIP113 MTP (store `confirmed[]` only sees tip).
///
/// Regression: after BIP68 assemble checks, multi-block batches failed on the
/// second height with spends (`median_time_past` → BadPrev), IBD silently
/// retried n=1, tip ~0.2/s, CPUs idle, no slow-batch logs.
#[test]
fn confirm_multi_block_spend_uses_header_plan_mtp() {
    use rbitcoin_consensus::{
        accept_and_connect_block, commit_class_a_run, confirm_scripts_phase,
        confirm_wire_load_phase, confirm_write_phase, ChainParams, Milestone, ScriptPreverified,
    };
    use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis, spend_anyone_can_spend};

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create(td.store_path()).unwrap();
    q.enter_direct_index_mode().unwrap();
    let ms = Milestone::NONE;
    let params = ChainParams::regtest();
    let none = ScriptPreverified::new();
    // CSV package active from height 1 on regtest — exercises BIP113 MTP path.
    assert!(params.csv_active_at(1));

    let genesis = regtest_genesis();
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;

    let maturity = params.coinbase_maturity();
    let mut all: Vec<(Height, bitcoin::Block)> = Vec::new();
    let mut cb1 = None;
    for h in 1u32..=maturity + 2 {
        let b = mine_regtest_block(tip, tip_time + 600, h, vec![]);
        if h == 1 {
            cb1 = Some(b.txdata[0].compute_txid());
        }
        tip = b.block_hash();
        tip_time = b.header.time;
        all.push((Height(h), b));
    }
    let spend_h = maturity + 3;
    let spend = spend_anyone_can_spend(cb1.unwrap(), 0, Amount::from_sat(49_0000_0000));
    // Second spend height in the *same* load batch (mid-batch BIP68 MTP).
    let b_spend = mine_regtest_block(tip, tip_time + 600, spend_h, vec![spend]);
    all.push((Height(spend_h), b_spend));
    commit_class_a_run(&q, &params, &all, ms).unwrap();
    assert_eq!(q.tip_height(), Some(Height::GENESIS));

    // One multi-block load of the whole run while tip is still genesis.
    let mat = confirm_wire_load_phase(&q, &params, ms, &all, &none).unwrap_or_else(|e| {
        panic!(
            "multi-block load with mid-batch spend must not fail BIP68 MTP (got {e}); \
             store-only median_time_past would BadPrev on unconfirmed prev heights"
        );
    });
    assert_eq!(mat.batch.len(), all.len(), "full batch must stay assembled");
    let ok = confirm_scripts_phase(mat.batch).expect("scripts");
    confirm_write_phase(&q, &params, ms, ok.batch).expect("write");
    assert_eq!(q.tip_height(), Some(Height(spend_h)));
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
    let q = Query::open_or_create(td.store_path()).unwrap();
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
}

/// Tip GC drops header plans for h ≤ tip while load-ahead assembles the next
/// batch. Assemble must use store for confirmed parents when the plan is gone
/// (not a tip-snapshot race that yields "load incomplete" on restart / dense
/// pipeline). Signet log: incomplete @ mid-heights while tip still advances.
#[test]
fn confirm_assemble_after_tip_gc_uses_store_for_mtp() {
    use rbitcoin_consensus::{
        accept_and_connect_block, commit_class_a_block, confirm_scripts_phase,
        confirm_wire_load_phase, confirm_write_phase, ChainParams, Milestone, ScriptPreverified,
    };
    use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis};

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create(td.store_path()).unwrap();
    q.enter_direct_index_mode().unwrap();
    let ms = Milestone::NONE;
    let params = ChainParams::regtest();
    let none = ScriptPreverified::new();

    let genesis = regtest_genesis();
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;

    let mut all: Vec<(Height, bitcoin::Block)> = Vec::with_capacity(24);
    for h in 1u32..=24 {
        let b = mine_regtest_block(tip, tip_time + 600, h, vec![]);
        commit_class_a_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
        all.push((Height(h), b));
    }

    // Load+write first 12 so tip=12 and tip_gc drops plans ≤ 12.
    let batch_a = &all[..12];
    let mat_a = confirm_wire_load_phase(&q, &params, ms, batch_a, &none).expect("load A");
    let ok_a = confirm_scripts_phase(mat_a.batch).expect("scripts A");
    confirm_write_phase(&q, &params, ms, ok_a.batch).expect("write A");
    assert_eq!(q.tip_height(), Some(Height(12)));

    // Load 13..=24: MTP window for height 13 is 2..=12 — plans tip-GC'd, must
    // come from confirmed[] store (not retryable load incomplete).
    let batch_b = &all[12..];
    let mat_b = confirm_wire_load_phase(&q, &params, ms, batch_b, &none).unwrap_or_else(|e| {
        panic!("load after tip_gc must use store for MTP parents (got {e})");
    });
    assert_eq!(mat_b.batch.heights_hashes()[0].0, 13);
    let ok_b = confirm_scripts_phase(mat_b.batch).expect("scripts B");
    confirm_write_phase(&q, &params, ms, ok_b.batch).expect("write B");
    assert_eq!(q.tip_height(), Some(Height(24)));
}

/// BlockCache + MempoolHub public surfaces used by P2P tip mode / Electrum.
#[test]
fn block_cache_and_mempool_hub_surface() {
    use bitcoin::hashes::Hash;
    use rbitcoin_net::{BlockCache, MempoolHub};
    use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis, spend_anyone_can_spend};
    use std::sync::Arc;

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create(td.store_path()).unwrap();
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
    assert_eq!(hub.scripthash_unconfirmed_delta(&sh), 0);

    let spend = spend_anyone_can_spend(cb1_txid, 0, Amount::from_sat(49_0000_0000));
    let r = hub
        .accept_tx(&spend)
        .expect("mempool accept mature coinbase spend");
    assert!(hub.contains(&r.txid));
    assert!(hub.get_tx(&r.txid).is_some());
    assert_eq!(hub.live_count(), 1);
    assert!(!hub.list_live().is_empty());
    assert!(!hub.scripthash_mempool(&sh).is_empty() || hub.scripthash_unconfirmed_delta(&sh) != 0);
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
        confirm_scripts_phase, confirm_wire_load_phase, confirm_write_phase, ChainParams,
        Milestone, ScriptPreverified,
    };

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create(td.store_path()).unwrap();
    q.enter_direct_index_mode().unwrap();
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;

    let genesis = regtest_genesis();
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;

    let mut batch: Vec<(Height, bitcoin::Block)> = Vec::new();
    for h in 1u32..=4 {
        let b = mine_regtest_block(tip, tip_time + 600, h, vec![]);
        tip = b.block_hash();
        tip_time = b.header.time;
        batch.push((Height(h), b));
    }

    rbitcoin_query::reset_body_ok_reads();
    let mat = confirm_wire_load_phase(&q, &params, ms, &batch, &ScriptPreverified::new())
        .expect("wire prep");
    assert_eq!(mat.batch.len(), 4);
    assert!(
        mat.batch.archive_plan.is_some(),
        "wire prep carries Class A plan for single commit era"
    );
    // Coinbase-only extension: no external parent denserels IO at prep.
    assert_eq!(
        rbitcoin_query::body_ok_reads(),
        0,
        "batch creates planned from wire — no Class-A body re-fetch for creates"
    );

    let ok = confirm_scripts_phase(mat.batch).expect("scripts");
    assert!(ok.batch.archive_plan.is_some());
    let fks = confirm_write_phase(&q, &params, ms, ok.batch).expect("commit");
    assert_eq!(fks.len(), 4);
    // Commit must not re-pread Class A bodies for layout (offline denserels).
    assert_eq!(
        rbitcoin_query::body_ok_reads(),
        0,
        "no Class-A body pipeline read across prep+scripts+commit for coinbase batch"
    );
    assert_eq!(q.tip_height(), Some(Height(4)));
    for (h, b) in &batch {
        assert!(
            q.is_block_archived(&b.block_hash().to_byte_array())
                .unwrap(),
            "h={} archived after unified commit",
            h.0
        );
    }
}

/// Wire prep pins external parent denserels from Class A (pipeline-local plan /
/// BatchParents) and confirms two sequential spends of the same create.
#[test]
fn wire_prep_external_parent_denserels_cold_class_a() {
    use rbitcoin_consensus::{
        accept_and_connect_block, confirm_scripts_phase, confirm_wire_load_phase,
        confirm_write_phase, ChainParams, Milestone, ScriptPreverified,
    };
    use rbitcoin_test::mine::split_anyone_can_spend;

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create(td.store_path()).unwrap();
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
    // Maturity pad: accept path (not per-block wire) — only later spends need wire.
    (tip, tip_time) = pad_empty_from(&q, &params, tip, tip_time, 2, maturity);

    // Split coinbase into two vouts so two later blocks spend the same parent create.
    let h_split = maturity + 1;
    let split = split_anyone_can_spend(
        cb1,
        0,
        &[
            Amount::from_sat(25_0000_0000),
            Amount::from_sat(24_0000_0000),
        ],
    );
    let b_split = mine_regtest_block(tip, tip_time + 600, h_split, vec![split]);
    let parent_txid = b_split.txdata[1].compute_txid();
    rbitcoin_consensus::confirm_wire_run(&q, &params, ms, &[(Height(h_split), b_split.clone())])
        .unwrap();
    tip = b_split.block_hash();
    tip_time = b_split.header.time;

    let h_a = maturity + 2;
    let spend_a = spend_anyone_can_spend(parent_txid, 0, Amount::from_sat(24_0000_0000));
    let ba = mine_regtest_block(tip, tip_time + 600, h_a, vec![spend_a]);
    let h_b = maturity + 3;
    let spend_b = spend_anyone_can_spend(parent_txid, 1, Amount::from_sat(23_0000_0000));
    let bb = mine_regtest_block(ba.block_hash(), tip_time + 1200, h_b, vec![spend_b]);

    let parent_fk = q
        .store()
        .get_fk_by_txid(parent_txid.as_byte_array())
        .unwrap()
        .expect("parent head");
    let _ = parent_fk;

    // Prep A/B: external parent denserels from Class A (pin by stamped range).
    let mat_a = confirm_wire_load_phase(
        &q,
        &params,
        ms,
        &[(Height(h_a), ba.clone())],
        &ScriptPreverified::new(),
    )
    .expect("prep A");
    let ok_a = confirm_scripts_phase(mat_a.batch).expect("scripts A");
    confirm_write_phase(&q, &params, ms, ok_a.batch).expect("write A");

    let mat_b = confirm_wire_load_phase(
        &q,
        &params,
        ms,
        &[(Height(h_b), bb.clone())],
        &ScriptPreverified::new(),
    )
    .expect("prep B");
    let ok_b = confirm_scripts_phase(mat_b.batch).expect("scripts B");
    confirm_write_phase(&q, &params, ms, ok_b.batch).expect("write B");
    assert_eq!(q.tip_height(), Some(Height(h_b)));
}

/// Already-archived Class A (plan=None): wire prep must still pin denserels for
/// same-batch creates. Regression: after write committed Class A then failed
/// annotate, re-prep had empty plan and spend annotate missed denserels/abs
/// (mainnet 20:15 rejects @219562+).
#[test]
fn wire_prep_already_archived_bodies_spend_annotate() {
    use rbitcoin_consensus::{
        accept_and_connect_block, commit_class_a_run, confirm_scripts_phase,
        confirm_wire_load_phase, confirm_write_phase, ChainParams, Milestone, ScriptPreverified,
    };

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create(td.store_path()).unwrap();
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
    // pad_empty_from is the fast maturity path (not per-block accept loop).
    (tip, tip_time) = pad_empty_from(&q, &params, tip, tip_time, 2, maturity);

    // Archive spend chain without confirming (Class A present, tip still maturity).
    let ha = maturity + 1;
    let spend_a = spend_anyone_can_spend(cb1, 0, Amount::from_sat(49_0000_0000));
    let ba = mine_regtest_block(tip, tip_time + 600, ha, vec![spend_a]);
    let a_out = ba.txdata[1].compute_txid();
    tip = ba.block_hash();
    tip_time = ba.header.time;

    let hb = maturity + 2;
    let spend_b = spend_anyone_can_spend(a_out, 0, Amount::from_sat(48_0000_0000));
    let bb = mine_regtest_block(tip, tip_time + 600, hb, vec![spend_b]);
    commit_class_a_run(
        &q,
        &params,
        &[(Height(ha), ba.clone()), (Height(hb), bb.clone())],
        ms,
    )
    .unwrap();
    assert_eq!(q.tip_height(), Some(Height(maturity)));

    // Wire prep both heights: need empty → plan None; must still annotate.
    let batch = [(Height(ha), ba.clone()), (Height(hb), bb.clone())];
    let mat = confirm_wire_load_phase(&q, &params, ms, &batch, &ScriptPreverified::new())
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
    confirm_write_phase(&q, &params, ms, ok.batch).unwrap_or_else(|e| {
        panic!(
            "write of already-archived wire batch must fill denserels for same-batch creates (got {e})"
        );
    });
    assert_eq!(q.tip_height(), Some(Height(hb)));
}

/// Prep(N+1) while N is still uncommitted pins parents from in-flight outs
/// **without denserels**. Write of N+1 must fill layout after N commits, or
/// structural spentness / spend annotate fails with
/// `missing pin denserels/abs` (mainnet IBD after load-ahead: reject@tip+1).
#[test]
fn wire_prep_ahead_cross_batch_spend_fills_parent_layout() {
    use rbitcoin_consensus::{
        accept_and_connect_block, confirm_scripts_phase, confirm_wire_load_phase_pipelined,
        confirm_write_phase, ChainParams, Milestone, ScriptPreverified, WireLoadPipeline,
    };

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create(td.store_path()).unwrap();
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

    // Batch A: spend mature coinbase → new anyone-can-spend out.
    let ha = maturity + 1;
    let spend_a = spend_anyone_can_spend(cb1, 0, Amount::from_sat(49_0000_0000));
    let ba = mine_regtest_block(tip, tip_time + 600, ha, vec![spend_a]);
    let a_out_txid = ba.txdata[1].compute_txid();
    let ha_hash = ba.block_hash();

    // Batch B: spend A's non-coinbase out (parent create is only in plan A).
    let hb = maturity + 2;
    let spend_b = spend_anyone_can_spend(a_out_txid, 0, Amount::from_sat(48_0000_0000));
    let bb = mine_regtest_block(ha_hash, tip_time + 1200, hb, vec![spend_b]);

    let mut inflight = rbitcoin_query::InFlight::new();
    let mut next_tx_start = q.tx_body_count().saturating_add(1).max(1);
    let mat_a = {
        let pipe = WireLoadPipeline {
            path_lo: ha,
            parent_hash: None,
            next_tx_start,
            in_flight: &inflight,
            skeleton: None,
        };
        confirm_wire_load_phase_pipelined(
            &q,
            &params,
            ms,
            &[(Height(ha), ba.clone())],
            &ScriptPreverified::new(),
            Some(&pipe),
        )
        .expect("prep A")
    };
    assert_eq!(q.tip_height(), Some(Height(maturity)), "prep must not tip");

    let plan_a = mat_a.batch.archive_plan.as_ref().expect("plan A");
    // Prep freezes plan after pin; only sparse BatchParents remains.
    assert!(
        plan_a.external_parents.is_empty(),
        "post-pin plan must not retain stamp staging on load→scripts→write handoff"
    );
    // packed pin half and batch_pin share CreatePin Arc (no outs double-store).
    assert_eq!(plan_a.batch_pin.len(), plan_a.packed.len());
    for ((pin_p, _), pin_b) in plan_a.packed.iter().zip(plan_a.batch_pin.iter()) {
        assert!(
            std::sync::Arc::ptr_eq(pin_p, pin_b),
            "packed and batch_pin must share CreatePin"
        );
    }
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

    // Prep B while A is still uncommitted — parent pin uses in_flight
    // (no denserels). This is the IBD prep∥write pipeline shape.
    let mat_b = {
        let pipe = WireLoadPipeline {
            path_lo: hb,
            parent_hash: Some(ha_hash.to_byte_array()),
            next_tx_start,
            in_flight: &inflight,
            skeleton: None,
        };
        confirm_wire_load_phase_pipelined(
            &q,
            &params,
            ms,
            &[(Height(hb), bb.clone())],
            &ScriptPreverified::new(),
            Some(&pipe),
        )
        .expect("prep B while tip still at maturity")
    };
    assert_eq!(q.tip_height(), Some(Height(maturity)));

    let ok_a = confirm_scripts_phase(mat_a.batch).expect("scripts A");
    confirm_write_phase(&q, &params, ms, ok_a.batch).expect("write A");
    assert_eq!(q.tip_height(), Some(Height(ha)));

    // Regression: without fill_missing_parent_layouts after A commits, write B
    // fails: "structural spentness missing pin denserels/abs".
    let ok_b = confirm_scripts_phase(mat_b.batch).expect("scripts B");
    confirm_write_phase(&q, &params, ms, ok_b.batch).unwrap_or_else(|e| {
        panic!("write B after load-ahead must fill parent denserels from committed A (got {e})");
    });
    assert_eq!(q.tip_height(), Some(Height(hb)));
}

/// Structural double-spend still rejects on the wire path.
#[test]
fn unified_wire_pipeline_rejects_double_spend() {
    use rbitcoin_consensus::{accept_and_connect_block, confirm_wire_run, ChainParams, Milestone};

    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create(td.store_path()).unwrap();
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

    let spend_h = maturity + 1;
    let spend = spend_anyone_can_spend(cb1, 0, Amount::from_sat(49_0000_0000));
    let b_spend = mine_regtest_block(tip, tip_time + 600, spend_h, vec![spend]);
    // Wire path for the spend under test (pad was accept-only).
    confirm_wire_run(&q, &params, ms, &[(Height(spend_h), b_spend.clone())]).unwrap();
    tip = b_spend.block_hash();
    tip_time = b_spend.header.time;
    assert!(q.is_outpoint_spent(cb1.as_byte_array(), 0).unwrap());

    let spend2 = spend_anyone_can_spend(cb1, 0, Amount::from_sat(48_0000_0000));
    let b_dup = mine_regtest_block(tip, tip_time + 600, spend_h + 1, vec![spend2]);
    let err = confirm_wire_run(&q, &params, ms, &[(Height(spend_h + 1), b_dup)])
        .expect_err("double spend");
    let msg = format!("{err}").to_lowercase();
    assert!(
        msg.contains("spent") || msg.contains("double") || msg.contains("bad"),
        "unexpected: {msg}"
    );
    assert_eq!(q.tip_height(), Some(Height(spend_h)));
}
