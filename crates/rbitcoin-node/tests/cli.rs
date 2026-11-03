use rbitcoin_consensus::default_milestone_height;
use rbitcoin_node::cli::*;
use rbitcoin_node::config::NodeConfig;
use rbitcoin_node::config::NodeEnv;
use rbitcoin_primitives::Network;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

/// [`NodeEnv::from_lookup`] over literal pairs, matched exactly. The last pair
/// for a name wins.
fn env_of(vars: &[(&str, &str)]) -> Result<NodeEnv, rbitcoin_node::NodeError> {
    NodeEnv::from_lookup(|k| {
        vars.iter()
            .rev()
            .find(|(name, _)| *name == k)
            .map(|(_, v)| OsString::from(v))
    })
}

fn tmp_datadir() -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("rbitcoin-cli-{n}"))
}

/// `ExitCode` is not `PartialEq`; compare via `Debug` (stable, sufficient for tests).
fn assert_exit(got: ExitCode, want: ExitCode) {
    assert_eq!(
        format!("{got:?}"),
        format!("{want:?}"),
        "exit code mismatch"
    );
}

#[test]
fn blocking_pool_is_capped_not_tokio_default() {
    assert!(blocking_pool_size() >= 4);
    assert!(blocking_pool_size() <= 512);
}

fn ready_config<I, T>(args: I) -> NodeConfig
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    match operator_config_from_args(args, &NodeEnv::default()) {
        Ok(OperatorArgs::Ready { config, .. }) => config,
        other => panic!("expected assembled config, got {other:?}"),
    }
}

/// What argv and the conf file assemble before `run_node`. The smoke
/// journey (`node_cli_and_surface_smoke`) sees only the exit code and
/// the datadir; these values and the help text are not reported by any
/// running surface, so this is the one place they are read.
#[allow(clippy::cognitive_complexity)] // one operator's conf and argv
#[test]
fn operator_conf_and_argv() {
    use rbitcoin_consensus::Milestone;
    use rbitcoin_node::config::P2pListen;
    let h = operator_usage();
    for flag in [
        "--prefill-compact",
        "--limit-cluster-count",
        "--limit-cluster-size",
        "--min-relay-tx-fee",
        "--mempool-expiry",
        "--external-ip",
        "--seed-node",
        "--mock-time",
        "--block-version",
        "--block-min-tx-fee",
        "--bytes-per-sigop",
        "--block-reserved-sigops",
        "--alert-notify",
        "--startup-notify",
        "--test-activation-height",
        "--regtest-pow-bits",
        "--rpc-work-queue",
        "--peer-timeout",
        "--blocks-only",
        "--ua-comment",
        "--min-chain-work",
        "--max-tip-age",
        "--check-blocks",
        "--net-permission",
        "--net-permission-bind",
        "--net-permission-relay",
        "--net-permission-force-relay",
        "--signet-block-time",
        "--sh-index",
        "--block-filter-index",
        "--prune-seqsigwit",
        "--datadir-hdd",
        "--prune-seqsigwit-ram-threshold-bytes",
        "--sp-tweaks",
        "--sp-tweaks-dust",
        "--esplora-block-template",
        "--esplora-onion",
        "--sv2-tp-listen",
        "--sv2-tp-authority-sec",
        "--sv2-tp-authority-sec-file",
        "--sv2-tp-cert-validity",
        "--sv2-tp-stale-grace",
        "--sv2-tp-idle-timeout",
        "--sv2-tp-fee-delta",
        "--sv2-tp-template-interval",
        "--rpc",
        "--rpc-listen",
        "--rest",
        "--rpc-socket",
        "--rpc-token-file",
        "--rpc-cookie-file",
        "--rpc-cookie-perms",
        "--proxy",
        "--onion",
        "--proxy-randomize",
        "--no-listen",
        "--no-discover",
        "--listen-onion",
        "--cjdns-reachable",
        "--tor-control",
        "--tor-control-cookie",
        "--tor-control-password",
        "--i2p-sam",
        "--i2p-accept-incoming",
    ] {
        assert!(h.contains(flag), "help must list {flag}");
    }
    for concat in [
        "--shindex",
        "--sptweaks",
        "-shindex",
        "-sptweaks",
        "--pruneseqsigwit",
        "--prefillcompact",
        "--limitclustercount",
        "--limitclustersize",
        "--minrelaytxfee",
        "--mempoolexpiry",
        "--externalip",
        "--seednode",
        "--mocktime",
        "--blockversion",
        "--blockmintxfee",
        "--alertnotify",
        "--startupnotify",
        "--testactivationheight",
        "--regtestpowbits",
        "--rpcworkqueue",
        "--checkblocks",
        "--blocksdir",
        "--blocks-dir",
        "--whitelist-relay",
        "--whitelist-forcerelay",
        "--nolisten",
        "--nodiscover",
        "--listenonion",
        "--cjdnsreachable",
        "--torcontrol",
        "--i2psam",
    ] {
        assert!(!h.contains(concat), "help must not advertise {concat}");
    }
    assert!(h.contains("Networks: mainnet|testnet|signet|regtest."));
    assert!(h.contains("[--signet-block-time SECS]"));
    assert!(matches!(
        operator_config_from_args(["rbitcoin-node", "-V"], &NodeEnv::default()),
        Ok(OperatorArgs::Version)
    ));
    assert!(matches!(
        operator_config_from_args(["rbitcoin-node", "--log-level=off"], &NodeEnv::default()),
        Ok(OperatorArgs::Ready {
            log_level_cli: Some(None),
            ..
        })
    ));

    let omitted = ready_config(["rbitcoin-node"]);
    assert_eq!(omitted.network, Network::Mainnet);
    assert_eq!(
        omitted.milestone_height,
        default_milestone_height(Network::Mainnet)
    );
    assert!(omitted.milestone().anchor.is_some());
    assert!(!omitted.milestone().skips_scripts_at(1));
    assert!(!omitted.meets_minimum_chain_work([0; 32]));
    assert!(omitted.prefill_compact);
    assert_eq!(omitted.check_blocks, None);
    assert_eq!(
        omitted.check_blocks_window(),
        rbitcoin_store::VERIFY_TIP_BLOCKS
    );
    assert!(omitted.listen.discover);
    assert_eq!(omitted.listen.p2p, P2pListen::Auto);
    assert_eq!(
        omitted.listen.p2p_bind_addr(Network::Regtest),
        Some("127.0.0.1:18444".parse().unwrap())
    );

    let dir = tmp_datadir();
    std::fs::create_dir_all(&dir).unwrap();
    let knobs = dir.join("rbitcoin.conf");
    std::fs::write(
        &knobs,
        "# custom signet\n\
         network=signet\n\
         signet_challenge=51\n\
         signet_block_time=60\n\
         max_inbound=40\n\
         max_outbound=8\n\
         mempool_size_mb=50\n\
         milestone=100\n\
         log_level=debug\n\
         api_log=/tmp/rbitcoin-api.jsonl\n\
         asmap=/tmp/ip_asn.dat\n\
         connect=127.0.0.1:38333\n\
         datadir-cold=/mnt/hdd/rbtc-cold\n",
    )
    .unwrap();
    let cfg = ready_config(["rbitcoin-node", "--conf", knobs.to_str().unwrap()]);
    assert_eq!(cfg.network, Network::Signet);
    let params = cfg.chain_params().unwrap();
    assert_eq!(params.btc.pow_target_spacing, 60);
    assert_eq!(params.signet_challenge.unwrap().as_bytes(), &[0x51]);
    assert_eq!(cfg.listen.max_inbound, 40);
    assert!(cfg.listen.max_inbound_explicit);
    assert_eq!(cfg.listen.max_outbound, 8);
    assert_eq!(cfg.mempool.max_weight, 50_000_000);
    assert_eq!(cfg.milestone_height, 100);
    assert_eq!(cfg.conf_log_level.as_deref(), Some("debug"));
    assert_eq!(
        cfg.api_log.as_deref(),
        Some(std::path::Path::new("/tmp/rbitcoin-api.jsonl"))
    );
    assert_eq!(
        cfg.asmap.as_deref(),
        Some(std::path::Path::new("/tmp/ip_asn.dat"))
    );
    assert_eq!(cfg.listen.connect.len(), 1);
    assert!(cfg.listen.connect_dns.is_empty());
    assert_eq!(
        cfg.datadir.cold.as_deref(),
        Some(std::path::Path::new("/mnt/hdd/rbtc-cold"))
    );

    // Bare network lines, and an explicit milestone 0 that the network
    // default does not replace, from the conf and from argv alike.
    for (bare, net) in [
        ("regtest", Network::Regtest),
        ("signet", Network::Signet),
        ("testnet", Network::Testnet),
    ] {
        let conf = dir.join(format!("{bare}.conf"));
        std::fs::write(&conf, format!("{bare}\n; also a comment\n\nno_seeds=1\n")).unwrap();
        let eq = format!("--conf={}", conf.to_str().unwrap());
        let cfg = ready_config(["rbitcoin-node", eq.as_str()]);
        assert_eq!(cfg.network, net);
        assert!(!cfg.listen.use_seeds);
    }
    let zero = dir.join("milestone.conf");
    std::fs::write(&zero, "milestone=0\n").unwrap();
    for cfg in [
        ready_config(["rbitcoin-node", "--conf", zero.to_str().unwrap()]),
        ready_config(["rbitcoin-node", "--milestone", "0"]),
    ] {
        assert_eq!(cfg.network, Network::Mainnet);
        assert_eq!(cfg.milestone(), Milestone::NONE);
    }
    // Conf `sp_tweaks` and `sp_tweaks_dust`, including dust 0 (serve every
    // output) and a value that does not parse.
    let sp = dir.join("sp.conf");
    std::fs::write(&sp, "sp_tweaks=1\n").unwrap();
    let sp_cfg = ready_config(["rbitcoin-node", "--conf", sp.to_str().unwrap()]);
    assert!(sp_cfg.sptweaks);
    assert_eq!(
        sp_cfg.sptweaks_dust,
        rbitcoin_electrum::DEFAULT_TWEAKS_MIN_DUST
    );
    sp_cfg.validate().expect("conf sp_tweaks=1");
    let dust = dir.join("dust.conf");
    std::fs::write(&dust, "sp_tweaks_dust=546\n").unwrap();
    assert_eq!(
        ready_config(["rbitcoin-node", "--conf", dust.to_str().unwrap()]).sptweaks_dust,
        546
    );
    let dust0 = dir.join("dust0.conf");
    std::fs::write(&dust0, "sp_tweaks_dust=0\n").unwrap();
    assert_eq!(
        ready_config(["rbitcoin-node", "--conf", dust0.to_str().unwrap()]).sptweaks_dust,
        0
    );
    let bad_dust = dir.join("dust-bad.conf");
    std::fs::write(&bad_dust, "sp_tweaks_dust=nope\n").unwrap();
    let err = NodeConfig::default()
        .merge_conf_file(&bad_dust)
        .unwrap_err()
        .to_string();
    assert!(err.contains("sp_tweaks_dust"), "{err}");
    match operator_config_from_args(
        ["rbitcoin-node", "--conf", bad_dust.to_str().unwrap()],
        &NodeEnv::default(),
    ) {
        Err(code) => assert_exit(code, ExitCode::from(2)),
        Ok(other) => panic!("bad sp_tweaks_dust conf assembled: {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
    let explicit = ready_config(["rbitcoin-node", "--milestone", "840000"]);
    assert!(explicit.milestone().anchor.is_none());
    assert!(explicit.milestone().skips_scripts_at(1));
    let signet = ready_config(["rbitcoin-node", "--network=signet"]);
    assert_eq!(signet.milestone_height, 0);
    assert!(!signet.milestone().skips_scripts_at(1));
    let testnet = ready_config(["rbitcoin-node", "--network=testnet"]);
    assert_eq!(testnet.milestone_height, 2_500_000);
    assert!(testnet.milestone().anchor.is_some());
    assert!(
        !testnet.milestone().skips_scripts_at(1),
        "anchored testnet milestone does not skip on height alone"
    );
    let signet_skip = ready_config([
        "rbitcoin-node",
        "--network=signet",
        "--milestone",
        "2000000",
    ]);
    assert!(signet_skip.milestone().skips_scripts_at(1));
    let work = ready_config(["rbitcoin-node", "--min-chain-work=0x65"]);
    assert_eq!(work.minimum_chain_work.unwrap()[31], 0x65);
    let mut long_work = NodeConfig::default();
    let long_hex = "01234567890123456789012345678901234567890123456789012345678901234";
    let refused = long_work
        .apply_kv("min_chain_work", long_hex)
        .unwrap_err()
        .to_string();
    assert!(
        refused.contains("64 hex digits"),
        "65 hex digits must be refused: {refused}"
    );

    // Kebab flags set the knob the conf key of the same name sets.
    let cfg = ready_config([
        "rbitcoin-node",
        "--network",
        "regtest",
        "--sh-index",
        "--sp-tweaks",
        "--sp-tweaks-dust=546",
        "--max-inbound",
        "0",
        "--no-discover",
        "--seed-node",
        "127.0.0.1:8333",
        "--min-relay-tx-fee",
        "0.00001000",
        "--rpc-listen",
        "--electrum-listen",
        "--esplora-listen",
        "--health-listen",
        "--metrics",
    ]);
    assert!(cfg.shindex && cfg.sptweaks);
    assert_eq!(cfg.sptweaks_dust, 546);
    assert_eq!(cfg.listen.max_inbound, 0);
    assert!(cfg.listen.max_inbound_explicit);
    assert!(!cfg.listen.discover);
    assert_eq!(cfg.listen.seednodes, vec!["127.0.0.1:8333".to_string()]);
    assert_eq!(cfg.mempool.min_relay_fee_btc.as_deref(), Some("0.00001000"));
    assert!(cfg.rpc.socket);
    assert_eq!(cfg.rpc.listen, Some("127.0.0.1:18443".parse().unwrap()));
    assert_eq!(cfg.listen.electrum.unwrap().port(), 50001);
    assert_eq!(cfg.listen.health, Some("127.0.0.1:9332".parse().unwrap()));
    assert!(cfg.metrics);
    match cfg.listen.esplora.unwrap() {
        rbitcoin_esplora::EsploraListen::Tcp(a) => assert_eq!(a.port(), 3000),
        #[cfg(unix)]
        rbitcoin_esplora::EsploraListen::Unix(_) => panic!("default esplora-listen is TCP"),
    }
    #[cfg(unix)]
    match ready_config(["rbitcoin-node", "--esplora-listen", "/tmp/esplora.sock"])
        .listen
        .esplora
        .unwrap()
    {
        rbitcoin_esplora::EsploraListen::Unix(p) => {
            assert_eq!(p, PathBuf::from("/tmp/esplora.sock"))
        }
        rbitcoin_esplora::EsploraListen::Tcp(_) => panic!("path must be unix"),
    }
    let sock = ready_config(["rbitcoin-node", "--rpc"]);
    assert!(sock.rpc.socket && sock.rpc.listen.is_none());
    let pruned = ready_config([
        "rbitcoin-node",
        "--prune-seqsigwit",
        "--prune-seqsigwit-ram-threshold-bytes=4096",
    ]);
    assert!(pruned.prune_seqsigwit);
    assert_eq!(pruned.prune_seqsigwit_ram_threshold_bytes, 4096);
    assert!(!ready_config(["rbitcoin-node"]).datadir_hdd);
    assert!(ready_config(["rbitcoin-node", "--datadir-hdd"]).datadir_hdd);
    let mut hdd_conf = NodeConfig::default();
    hdd_conf.apply_kv("datadir_hdd", "1").unwrap();
    assert!(hdd_conf.datadir_hdd);
    for (argv, want) in [
        (&["--prefill-compact=0"][..], false),
        (&["--prefill-compact"], true),
        (&["--prefill-compact=1"], true),
    ] {
        let mut args = vec!["rbitcoin-node"];
        args.extend_from_slice(argv);
        assert_eq!(ready_config(args).prefill_compact, want, "{argv:?}");
    }
    for (arg, stored, window) in [
        ("--check-blocks=6", 6, 6),
        ("--check-blocks=0", 0, 0),
        ("--check-blocks=-1", -1, 0),
    ] {
        let cfg = ready_config(["rbitcoin-node", arg]);
        assert_eq!(cfg.check_blocks, Some(stored));
        assert_eq!(cfg.check_blocks_window(), window, "{arg}");
    }
    for off in ["--no-listen", "--listen=0"] {
        let cfg = ready_config(["rbitcoin-node", off]);
        assert_eq!(cfg.listen.p2p, P2pListen::Off, "{off}");
        assert!(cfg.listen.p2p_bind_addr(Network::Regtest).is_none());
    }
    let bound = ready_config(["rbitcoin-node", "--listen", "127.0.0.1:18445"]);
    assert_eq!(
        bound.listen.p2p_bind_addr(Network::Regtest),
        Some("127.0.0.1:18445".parse().unwrap())
    );

    assert_eq!(
        ready_config(["rbitcoin-node"]).mempool.bytes_per_sigop,
        None
    );
    assert_eq!(
        ready_config(["rbitcoin-node", "--bytes-per-sigop", "0"])
            .mempool
            .bytes_per_sigop,
        Some(0)
    );
    assert_eq!(
        ready_config(["rbitcoin-node", "--bytes-per-sigop=40"])
            .mempool
            .bytes_per_sigop,
        Some(40)
    );
    assert_exit(
        cli_main(["rbitcoin-node", "--bytes-per-sigop=x"], NodeEnv::default()),
        ExitCode::from(2),
    );
    assert_eq!(
        ready_config(["rbitcoin-node", "--block-reserved-sigops", "0"])
            .mempool
            .block_reserved_sigops,
        Some(0)
    );
    assert_eq!(
        ready_config(["rbitcoin-node", "--block-reserved-sigops=400"])
            .mempool
            .block_reserved_sigops,
        Some(400)
    );
    let mut over = ready_config(["rbitcoin-node", "--block-reserved-sigops", "80001"]);
    assert!(over.validate().is_err());
    over.mempool.block_reserved_sigops = Some(80_000);
    over.validate().expect("consensus maximum is accepted");

    let tweaks = ready_config(["rbitcoin-node", "--sp-tweaks", "--prune-seqsigwit"]);
    let err = tweaks.validate().unwrap_err().to_string();
    assert!(
        err.contains("--sp-tweaks") && err.contains("--prune-seqsigwit"),
        "{err}"
    );
    let mut conf = NodeConfig::default();
    conf.apply_kv("prune_seqsigwit", "1").unwrap();
    conf.apply_kv("sp_tweaks", "1").unwrap();
    assert!(conf.validate().is_err());

    // Electrum and Esplora do not require the scripthash index. The index
    // may also stand alone, or run with either listener.
    for argv in [
        &["--electrum-listen"][..],
        &["--esplora-listen"],
        &["--sh-index"],
        &["--sh-index", "--electrum-listen"],
        &["--sh-index", "--esplora-listen"],
    ] {
        let mut args = vec!["rbitcoin-node", "--network", "regtest"];
        args.extend_from_slice(argv);
        ready_config(args)
            .validate()
            .unwrap_or_else(|e| panic!("{argv:?} must validate: {e}"));
    }

    // Zero is the finite default queue, not an unbounded one.
    assert_eq!(
        ready_config(["rbitcoin-node"]).rpc.work_queue,
        Some(rbitcoin_rpc::DEFAULT_RPC_WORK_QUEUE)
    );
    assert_eq!(
        ready_config(["rbitcoin-node", "--rpc-work-queue=0"])
            .rpc
            .work_queue,
        Some(rbitcoin_rpc::DEFAULT_RPC_WORK_QUEUE)
    );
    assert_eq!(
        ready_config(["rbitcoin-node", "--rpc-work-queue=4"])
            .rpc
            .work_queue,
        Some(4)
    );
}

#[test]
fn esplora_max_inflight_cli_conf_and_bounds() {
    assert_eq!(
        ready_config(["rbitcoin-node"]).esplora_max_inflight,
        rbitcoin_electrum::DEFAULT_MAX_CONNECTIONS
    );
    assert_eq!(
        ready_config(["rbitcoin-node", "--esplora-max-inflight", "1024"]).esplora_max_inflight,
        1024
    );
    assert_eq!(
        ready_config(["rbitcoin-node", "--esplora-max-inflight=8"]).esplora_max_inflight,
        8
    );
    let mut c = NodeConfig::default();
    let zero = c.apply_kv("esplora_max_inflight", "0").unwrap_err();
    assert!(format!("{zero}").contains(">= 1"), "{zero}");
    let bad = c.apply_kv("esplora_max_inflight", "nope").unwrap_err();
    assert!(format!("{bad}").contains("esplora_max_inflight"), "{bad}");
    let max = tokio::sync::Semaphore::MAX_PERMITS;
    let over = c
        .apply_kv("esplora_max_inflight", &(max + 1).to_string())
        .unwrap_err();
    assert!(format!("{over}").contains("<="), "{over}");
    let huge = c
        .apply_kv("esplora_max_inflight", "9999999999999999999")
        .unwrap_err();
    assert!(format!("{huge}").contains("esplora_max_inflight"), "{huge}");
    assert_eq!(
        c.esplora_max_inflight,
        rbitcoin_electrum::DEFAULT_MAX_CONNECTIONS,
        "a refused value leaves the default"
    );
}

#[test]
fn sv2_tp_idle_timeout_argv_default_off() {
    use std::time::Duration;
    assert_eq!(
        ready_config(["rbitcoin-node"]).sv2_tp_idle_timeout,
        Duration::ZERO
    );
    assert_eq!(
        ready_config(["rbitcoin-node", "--sv2-tp-idle-timeout", "90"]).sv2_tp_idle_timeout,
        Duration::from_secs(90)
    );
    assert_eq!(
        ready_config(["rbitcoin-node", "--sv2-tp-idle-timeout=0"]).sv2_tp_idle_timeout,
        Duration::ZERO
    );
    for bad in ["86401", "-1", "x"] {
        assert!(
            operator_config_from_args(
                ["rbitcoin-node", "--sv2-tp-idle-timeout", bad],
                &NodeEnv::default()
            )
            .is_err(),
            "{bad}"
        );
    }
}

#[test]
fn electrum_max_subs_cli_conf_and_bounds() {
    assert_eq!(
        ready_config(["rbitcoin-node"]).electrum_max_subs,
        rbitcoin_electrum::DEFAULT_MAX_SCRIPTHASH_SUBS
    );
    assert_eq!(
        ready_config(["rbitcoin-node", "--electrum-max-subs", "25000"]).electrum_max_subs,
        25_000
    );
    assert_eq!(
        ready_config(["rbitcoin-node", "--electrum-max-subs=5"]).electrum_max_subs,
        5
    );
    let mut c = NodeConfig::default();
    let zero = c.apply_kv("electrum_max_subs", "0").unwrap_err();
    assert!(format!("{zero}").contains(">= 1"), "{zero}");
    let bad = c.apply_kv("electrum_max_subs", "nope").unwrap_err();
    assert!(format!("{bad}").contains("electrum_max_subs"), "{bad}");
    assert_eq!(
        c.electrum_max_subs,
        rbitcoin_electrum::DEFAULT_MAX_SCRIPTHASH_SUBS,
        "a refused value leaves the default"
    );
}

#[test]
fn max_sh_creates_and_esplora_block_template_cli_hyphens() {
    let omitted = ready_config(["rbitcoin-node"]);
    assert_eq!(
        omitted.max_sh_creates,
        rbitcoin_query::DEFAULT_MAX_SH_CREATES
    );
    assert!(!omitted.esplora_block_template);
    let n = ready_config(["rbitcoin-node", "--max-sh-creates", "42"]);
    assert_eq!(n.max_sh_creates, 42);
    let eq = ready_config(["rbitcoin-node", "--max-sh-creates=9"]);
    assert_eq!(eq.max_sh_creates, 9);
    assert_eq!(
        omitted.heavy_sh_creates,
        rbitcoin_query::DEFAULT_HEAVY_SH_CREATES
    );
    let heavy = ready_config(["rbitcoin-node", "--heavy-sh-creates", "500"]);
    assert_eq!(heavy.heavy_sh_creates, 500);
    let gbt = ready_config(["rbitcoin-node", "--esplora-block-template"]);
    assert!(gbt.esplora_block_template);
    let gbt_eq = ready_config(["rbitcoin-node", "--esplora-block-template=1"]);
    assert!(gbt_eq.esplora_block_template);
    let off = ready_config(["rbitcoin-node", "--esplora-block-template=0"]);
    assert!(!off.esplora_block_template);
    assert!(NodeConfig::default().esplora_onion);
    let onion_off = ready_config(["rbitcoin-node", "--esplora-onion=0"]);
    assert!(!onion_off.esplora_onion);
}

include!("overlay_config_journey.rs");

/// Testnet3 default milestone: Core's assumeutxo block at 2_500_000 and
/// Core `CTestNetParams` `nMinimumChainWork`, like mainnet's 840_000.
#[test]
fn testnet3_default_milestone_is_anchored() {
    use bitcoin::hashes::Hash;
    let cfg = ready_config(["rbitcoin-node", "--network", "testnet"]);
    assert_eq!(cfg.network, Network::Testnet);
    let m = cfg.milestone();
    assert_eq!(m.height, 2_500_000);
    let anchor = m.anchor.expect("testnet3 default milestone is anchored");
    assert_eq!(
        anchor.hash.to_string(),
        "0000000000000093bcb68c03a9a168ae252572d348a2eaeba2cdf9231d73206f"
    );
    let mut min_work = [0u8; 32];
    min_work[22..].copy_from_slice(&[0x17, 0xf4, 0x9f, 0x70, 0x21, 0x47, 0xf1, 0x0c, 0x0e, 0xb6]);
    assert_eq!(anchor.min_work_be, min_work);
    assert!(cfg.meets_minimum_chain_work(min_work));
    let mut below = min_work;
    below[31] -= 1;
    assert!(!cfg.meets_minimum_chain_work(below));

    // A chain without the anchor at 2_500_000 runs scripts at any height.
    let block = [0x22u8; 32];
    let other_chain = |h: u32| (h == 100).then_some(block).or(Some([0x33; 32]));
    assert!(!m.skips_scripts_at(100));
    assert!(!m.skips_scripts(100, &block, other_chain));
    let anchored = |h: u32| match h {
        100 => Some(block),
        2_500_000 => Some(anchor.hash.to_byte_array()),
        _ => None,
    };
    assert!(
        m.skips_scripts(100, &block, anchored),
        "the anchor hash is enough; chain work below the floor still skips"
    );

    // Explicit `--milestone HEIGHT` stays height-only.
    let explicit = ready_config(["rbitcoin-node", "--network", "testnet", "--milestone", "10"]);
    assert_eq!(
        explicit.milestone(),
        rbitcoin_consensus::Milestone::height(10)
    );
}

/// RPC binds only after catch-up, so a bad `--rpc-cookie-file` must fail
/// the launch rather than surface as a warning after IBD.
#[test]
fn cli_rejects_bad_rpc_cookie_at_launch() {
    let dir = tmp_datadir();
    std::fs::create_dir_all(&dir).unwrap();
    let cookie = dir.join("rpc.cookie");
    let run = |extra: &[&str]| {
        let mut args = vec![
            "rbitcoin-node",
            "--smoke",
            "--network",
            "regtest",
            "--datadir",
            dir.to_str().unwrap(),
            "--log-level",
            "error",
            "--no-seeds",
            "--milestone",
            "0",
            "--rpc-cookie-file",
            cookie.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        cli_main(args, NodeEnv::default())
    };
    assert_exit(run(&["--rpc-listen"]), ExitCode::FAILURE);
    std::fs::write(&cookie, "__cookie__:secret\n").unwrap();
    assert_exit(run(&["--rpc-listen"]), ExitCode::FAILURE);
    std::fs::write(&cookie, "__cookie__:secret").unwrap();
    // Socket-only RPC would silently ignore the cookie (message pinned in config.rs).
    assert_exit(run(&["--rpc"]), ExitCode::FAILURE);
    assert_exit(
        run(&["--rpc-listen", "--rpc-cookie-perms", "0640"]),
        ExitCode::from(2),
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cookie, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_exit(run(&["--rpc-listen"]), ExitCode::FAILURE);
        std::fs::set_permissions(&cookie, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_exit(
            run(&["--rpc-listen", "--rpc-cookie-perms", "group"]),
            ExitCode::SUCCESS,
        );
        std::fs::set_permissions(&cookie, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_exit(run(&["--rpc-listen"]), ExitCode::SUCCESS);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `RBITCOIN_P2P_MAX_INBOUND` sets the inbound cap only when CLI and conf
/// omit it. `0` is no inbound slots, as `--max-inbound 0` is. Empty is unset.
#[test]
fn inbound_env_is_below_cli_and_conf() {
    use rbitcoin_node::config::DEFAULT_MAX_INBOUND;
    let inbound = |args: &[&str], val: &str| {
        let env = env_of(&[("RBITCOIN_P2P_MAX_INBOUND", val)]).unwrap();
        let args = std::iter::once("rbitcoin-node").chain(args.iter().copied());
        match operator_config_from_args(args, &env) {
            Ok(OperatorArgs::Ready { config, .. }) => config.listen.max_inbound,
            other => panic!("expected assembled config, got {other:?}"),
        }
    };
    assert_eq!(inbound(&[], "91"), 91);
    assert_eq!(inbound(&["--max-inbound", "12"], "91"), 12);
    assert_eq!(inbound(&[], "0"), 0);
    assert_eq!(inbound(&[], ""), DEFAULT_MAX_INBOUND);

    let conf_dir = tmp_datadir();
    std::fs::create_dir_all(&conf_dir).unwrap();
    let conf = conf_dir.join("rbitcoin.conf");
    std::fs::write(&conf, "max_inbound=7\n").unwrap();
    assert_eq!(inbound(&["--conf", conf.to_str().unwrap()], "91"), 7);
    let _ = std::fs::remove_dir_all(&conf_dir);
}

/// `RBITCOIN_BLOCK_QUEUE_BYTES` wins over `RBITCOIN_BLOCK_QUEUE_GB`. `0` is
/// unlimited. Empty is unset.
#[test]
fn block_queue_env_sets_the_assign_stop() {
    use rbitcoin_query::BQ_ASSIGN_STOP_BYTES;
    const BYTES: &str = "RBITCOIN_BLOCK_QUEUE_BYTES";
    const GB: &str = "RBITCOIN_BLOCK_QUEUE_GB";
    let stop = |vars: &[(&str, &str)]| {
        let env = env_of(vars).unwrap();
        match operator_config_from_args(["rbitcoin-node"], &env) {
            Ok(OperatorArgs::Ready { config, .. }) => config.bq_assign_stop_bytes,
            other => panic!("expected assembled config, got {other:?}"),
        }
    };
    assert_eq!(stop(&[]), BQ_ASSIGN_STOP_BYTES);
    assert_eq!(stop(&[(GB, "2")]), 2 << 30);
    assert_eq!(stop(&[(GB, "2"), (BYTES, "4096")]), 4096);
    assert_eq!(stop(&[(BYTES, "4096"), (GB, "2")]), 4096);
    assert_eq!(stop(&[(GB, "0")]), u64::MAX);
    assert_eq!(stop(&[(BYTES, "0"), (GB, "2")]), u64::MAX);
    assert_eq!(stop(&[(BYTES, ""), (GB, "2")]), 2 << 30);
    assert_eq!(stop(&[(GB, "")]), BQ_ASSIGN_STOP_BYTES);
}

/// `RBITCOIN_TEST_DROP_STORE`, `RBITCOIN_SH_FORCE_REBUILD`,
/// `RBITCOIN_RPC_PACKAGE_DIALECT`, and `RBITCOIN_RPC_WAIT_TIP_IDLE` are on for
/// `1` or `true` and off for `0`, `false`, or empty (`true`/`false` in any
/// case). All but the first reach `NodeConfig`.
#[test]
fn env_flags_take_one_true_zero_or_false() {
    const KEYS: [&str; 4] = [
        "RBITCOIN_TEST_DROP_STORE",
        "RBITCOIN_SH_FORCE_REBUILD",
        "RBITCOIN_RPC_PACKAGE_DIALECT",
        "RBITCOIN_RPC_WAIT_TIP_IDLE",
    ];
    let flags = |key: &str, val: &str| {
        let env = env_of(&[(key, val)]).unwrap();
        [
            env.test_drop_store,
            env.sh_force_rebuild,
            env.rpc_package_dialect,
            env.rpc_wait_tip_idle,
        ]
    };
    for on in ["1", "true", "TRUE", "True"] {
        for (i, key) in KEYS.iter().enumerate() {
            let mut want = [false; 4];
            want[i] = true;
            assert_eq!(flags(key, on), want, "{key}={on:?}");
        }
    }
    for off in ["", "0", "false", "FALSE"] {
        for key in KEYS {
            assert_eq!(flags(key, off), [false; 4], "{key}={off:?}");
        }
    }
    assert_eq!(env_of(&[]).unwrap(), NodeEnv::default());

    let env = env_of(&[
        ("RBITCOIN_SH_FORCE_REBUILD", "1"),
        ("RBITCOIN_RPC_PACKAGE_DIALECT", "1"),
        ("RBITCOIN_RPC_WAIT_TIP_IDLE", "1"),
    ])
    .unwrap();
    match operator_config_from_args(["rbitcoin-node"], &env) {
        Ok(OperatorArgs::Ready { config, .. }) => {
            assert!(config.sh_force_rebuild);
            assert!(config.rpc.package_dialect);
            assert!(config.rpc.wait_tip_idle);
        }
        other => panic!("expected assembled config, got {other:?}"),
    }
}

/// `NodeEnv` asks its lookup for each knob by name and leaves the name match to
/// it. `std::env::var_os` ignores case on Windows, so there a lower-case name
/// still sets the knob, as it did before `NodeEnv`.
#[test]
fn env_lookup_owns_the_name_match() {
    let ignore_case = |k: &str| {
        k.eq_ignore_ascii_case("rbitcoin_sh_force_rebuild")
            .then(|| OsString::from("1"))
    };
    assert!(NodeEnv::from_lookup(ignore_case).unwrap().sh_force_rebuild);
    assert!(
        !env_of(&[("rbitcoin_sh_force_rebuild", "1")])
            .unwrap()
            .sh_force_rebuild
    );
}

/// A set `RBITCOIN_*` value that does not parse is an error naming the var,
/// not a silent default. Other env is not read.
#[test]
fn malformed_env_names_the_var() {
    for (key, val) in [
        ("RBITCOIN_P2P_MAX_INBOUND", "many"),
        ("RBITCOIN_P2P_MAX_INBOUND", "-1"),
        ("RBITCOIN_BLOCK_QUEUE_BYTES", "4k"),
        ("RBITCOIN_BLOCK_QUEUE_GB", "1.5"),
        ("RBITCOIN_TEST_DROP_STORE", "yes"),
        ("RBITCOIN_SH_FORCE_REBUILD", "on"),
        ("RBITCOIN_RPC_PACKAGE_DIALECT", " 1"),
        ("RBITCOIN_RPC_WAIT_TIP_IDLE", "ture"),
    ] {
        let err = env_of(&[(key, val)]).unwrap_err().to_string();
        assert!(
            err.contains(key) && err.contains(val),
            "{key}={val:?}: {err}"
        );
    }
    let err = env_of(&[
        ("RBITCOIN_BLOCK_QUEUE_BYTES", "4096"),
        ("RBITCOIN_BLOCK_QUEUE_GB", "lots"),
    ])
    .unwrap_err();
    assert!(err.to_string().contains("RBITCOIN_BLOCK_QUEUE_GB"), "{err}");
    assert!(env_of(&[("PATH", "not a number"), ("RBITCOIN_NOT_A_KNOB", "x")]).is_ok());

    #[cfg(unix)]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let bad = OsStr::from_bytes(&[0xff, 0x31]);
        let err =
            NodeEnv::from_lookup(|k| (k == "RBITCOIN_SH_FORCE_REBUILD").then(|| bad.to_owned()))
                .unwrap_err();
        assert!(
            err.to_string().contains("RBITCOIN_SH_FORCE_REBUILD"),
            "{err}"
        );
    }
}

/// `--trust-peer ADDR` is the only dial target. Clashing flags fail in the
/// parser, before `ensure_datadir` creates a store.
#[test]
fn trust_peer_addr() {
    use rbitcoin_node::config::P2pListen;
    use rbitcoin_node::config::DEFAULT_MAX_INBOUND;

    let h = operator_usage();
    assert!(
        h.contains("--trust-peer ADDR"),
        "help must name --trust-peer with an address"
    );

    let missing = operator_config_from_args(["rbitcoin-node", "--trust-peer"], &NodeEnv::default());
    assert!(missing.is_err(), "bare --trust-peer must not start");

    let dir = tmp_datadir();
    let addr = "192.0.2.1:8333";
    let cfg = ready_config([
        "rbitcoin-node",
        "--datadir",
        dir.to_str().unwrap(),
        "--trust-peer",
        addr,
    ]);
    assert_eq!(cfg.trust_peer.map(|a| a.to_string()).as_deref(), Some(addr));
    assert!(cfg.trust_peer_host.is_none());
    assert_eq!(cfg.listen.connect.len(), 1);
    assert_eq!(cfg.listen.connect[0].to_string(), addr);
    assert!(cfg.listen.connect_dns.is_empty());
    assert!(!cfg.listen.use_seeds);
    assert!(matches!(cfg.listen.p2p, P2pListen::Off));
    assert!(cfg.listen.p2p_extra.is_empty());
    assert!(!cfg.listen.listen_onion);
    assert!(cfg.listen.seednodes.is_empty());
    assert_eq!(cfg.listen.max_inbound, 0);
    assert!(!dir.exists(), "parser must not create the datadir");

    let plain = ready_config(["rbitcoin-node", "--datadir", dir.to_str().unwrap()]);
    assert!(plain.trust_peer.is_none());
    assert!(plain.trust_peer_host.is_none());
    assert!(plain.listen.connect.is_empty());
    assert!(plain.listen.use_seeds);
    assert!(matches!(plain.listen.p2p, P2pListen::Auto));
    assert_eq!(plain.listen.max_inbound, DEFAULT_MAX_INBOUND);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The same address may also be `--connect`. A hostname is the connect-dns row.
#[test]
fn trust_peer_same_connect_and_host() {
    use rbitcoin_node::config::P2pListen;
    let dir = tmp_datadir();
    let addr = "192.0.2.1:8333";
    let same = ready_config([
        "rbitcoin-node",
        "--datadir",
        dir.to_str().unwrap(),
        "--connect",
        addr,
        "--trust-peer",
        addr,
        "--no-listen",
        "--max-inbound",
        "0",
    ]);
    assert_eq!(same.listen.connect.len(), 1);
    assert_eq!(same.listen.connect[0].to_string(), addr);
    assert_eq!(same.listen.max_inbound, 0);

    let dns = ready_config([
        "rbitcoin-node",
        "--datadir",
        dir.to_str().unwrap(),
        "--trust-peer",
        "seed.example:8333",
    ]);
    assert!(dns.trust_peer.is_none());
    assert_eq!(dns.trust_peer_host.as_deref(), Some("seed.example:8333"));
    assert!(dns.listen.connect.is_empty());
    assert_eq!(
        dns.listen.connect_dns,
        vec!["seed.example:8333".to_string()]
    );
    assert!(!dns.listen.use_seeds);
    assert!(matches!(dns.listen.p2p, P2pListen::Off));

    let conf = dir.join("trust.conf");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(&conf, "trustpeer=192.0.2.1:8333\n").unwrap();
    let from_conf = ready_config([
        "rbitcoin-node",
        "--datadir",
        dir.to_str().unwrap(),
        "--conf",
        conf.to_str().unwrap(),
    ]);
    assert_eq!(
        from_conf.trust_peer.map(|a| a.to_string()).as_deref(),
        Some(addr)
    );
    assert!(matches!(from_conf.listen.p2p, P2pListen::Off));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A second address, a different connect, seeds, listen, or inbound is a start error.
#[test]
fn trust_peer_clashing_flags() {
    let dir = tmp_datadir();
    let addr = "192.0.2.1:8333";
    let clashes: &[&[&str]] = &[
        &["--trust-peer", addr, "--trust-peer", "192.0.2.2:8333"],
        &["--trust-peer", addr, "--connect", "192.0.2.2:8333"],
        &["--trust-peer", addr, "--seed-node", "192.0.2.9:8333"],
        &["--trust-peer", addr, "--listen", "127.0.0.1:8333"],
        &["--trust-peer", addr, "--listen-onion"],
        &["--trust-peer", addr, "--max-inbound", "1"],
        &["--connect", "seed.example:8333", "--trust-peer", addr],
    ];
    for extra in clashes {
        let mut args = vec!["rbitcoin-node", "--datadir", dir.to_str().unwrap()];
        args.extend_from_slice(extra);
        assert!(
            operator_config_from_args(args, &NodeEnv::default()).is_err(),
            "expected start error for {extra:?}"
        );
        assert!(!dir.exists(), "clash must not create the datadir");
    }

    let mut cfg = rbitcoin_node::config::NodeConfig::default();
    cfg.apply_kv("trust_peer", addr).unwrap();
    cfg.apply_kv("listen", "127.0.0.1:8333").unwrap();
    let err = cfg.seal_trust_peer().unwrap_err().to_string();
    assert!(err.contains("trust-peer"), "{err}");
    assert!(err.contains("--listen"), "{err}");

    let mut cfg = rbitcoin_node::config::NodeConfig::default();
    cfg.apply_kv("trustpeer", addr).unwrap();
    cfg.apply_kv("max_inbound", "8").unwrap();
    let err = cfg.seal_trust_peer().unwrap_err().to_string();
    assert!(err.contains("--max-inbound"), "{err}");

    let mut cfg = rbitcoin_node::config::NodeConfig::default();
    cfg.apply_kv("trust_peer", addr).unwrap();
    let err = cfg
        .apply_kv("trustpeer", "192.0.2.2:8333")
        .unwrap_err()
        .to_string();
    assert!(err.contains("exactly one"), "{err}");

    let mut bare = rbitcoin_node::config::NodeConfig::default();
    bare.apply_kv("trust_peer", addr).unwrap();
    let err = bare.validate().unwrap_err().to_string();
    assert!(err.contains("--listen"), "{err}");

    let mut sealed = rbitcoin_node::config::NodeConfig::default();
    sealed.apply_kv("trust_peer", addr).unwrap();
    sealed.seal_trust_peer().unwrap();
    sealed.validate().unwrap();

    // Listen fields stay writable. Validate still rejects the clashes.
    sealed.listen.p2p = rbitcoin_node::config::P2pListen::Auto;
    let err = sealed.validate().unwrap_err().to_string();
    assert!(err.contains("--listen"), "{err}");

    sealed.listen.p2p = rbitcoin_node::config::P2pListen::Off;
    sealed
        .listen
        .p2p_extra
        .push("127.0.0.1:8334".parse().unwrap());
    let err = sealed.validate().unwrap_err().to_string();
    assert!(err.contains("--listen"), "{err}");
    sealed.listen.p2p_extra.clear();

    sealed.listen.listen_onion = true;
    let err = sealed.validate().unwrap_err().to_string();
    assert!(err.contains("--listen"), "{err}");
    assert!(
        !err.contains("listen-onion requires"),
        "onion after a seal is the trust-peer listen clash: {err}"
    );

    sealed.listen.listen_onion = false;
    sealed.tor.control = None;
    sealed.listen.max_inbound = 1;
    let err = sealed.validate().unwrap_err().to_string();
    assert!(err.contains("--max-inbound"), "{err}");

    sealed.listen.max_inbound = 0;
    sealed.listen.use_seeds = true;
    let err = sealed.validate().unwrap_err().to_string();
    assert!(err.contains("--seed-node"), "{err}");

    sealed.listen.use_seeds = false;
    sealed.listen.seednodes.push("seed.example".into());
    let err = sealed.validate().unwrap_err().to_string();
    assert!(err.contains("--seed-node"), "{err}");
}

#[test]
fn regtest_pow_bits_from_argv_and_conf() {
    let bits = |cfg: &NodeConfig| cfg.chain_params().map(|p| p.regtest_pow_bits_overlay);
    assert_eq!(
        bits(&ready_config(["rbitcoin-node", "--network=regtest"])).unwrap(),
        None
    );
    for (arg, want) in [
        ("--regtest-pow-bits=0x200fffff", 0x200f_ffff),
        ("--regtest-pow-bits=200fffff", 0x200f_ffff),
    ] {
        let cfg = ready_config(["rbitcoin-node", "--network=regtest", arg]);
        assert_eq!(cfg.regtest_pow_bits, Some(want));
        assert_eq!(bits(&cfg).unwrap().map(|b| b.to_consensus()), Some(want));
    }

    let dir = tmp_datadir();
    std::fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("pow.conf");
    std::fs::write(&conf, "regtest\nregtest_pow_bits=0x1f7fffff\n").unwrap();
    let cfg = ready_config(["rbitcoin-node", "--conf", conf.to_str().unwrap()]);
    assert_eq!(cfg.regtest_pow_bits, Some(0x1f7f_ffff));
    assert!(cfg.chain_params().is_ok());

    // Off regtest, or with a value that is not a harder regtest target.
    let off = ready_config([
        "rbitcoin-node",
        "--network=signet",
        "--regtest-pow-bits=0x200fffff",
    ]);
    let err = off.chain_params().unwrap_err().to_string();
    assert!(err.contains("regtest only"), "{err}");
    let easy = ready_config([
        "rbitcoin-node",
        "--network=regtest",
        "--regtest-pow-bits=0x2100ffff",
    ]);
    assert!(easy.chain_params().is_err());
    assert!(operator_config_from_args(
        ["rbitcoin-node", "--regtest-pow-bits=nothex"],
        &NodeEnv::default()
    )
    .is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn store_read_budget_formula_and_flag() {
    assert_eq!(store_read_budget(true, 4, None), 1);
    assert_eq!(store_read_budget(true, 4, Some(0)), 1);
    assert_eq!(store_read_budget(false, 4, None), 3);
    assert_eq!(store_read_budget(false, 4, Some(0)), 3);
    assert_eq!(store_read_budget(false, 1, None), 1);
    assert_eq!(store_read_budget(true, 64, Some(8)), 8);
    assert_eq!(store_read_budget(false, 64, Some(8)), 8);

    assert_eq!(ready_config(["rbitcoin-node"]).store_read_budget, None);
    assert_eq!(
        ready_config(["rbitcoin-node", "--store-read-budget", "0"]).store_read_budget,
        Some(0)
    );
    assert_eq!(
        ready_config(["rbitcoin-node", "--store-read-budget=12"]).store_read_budget,
        Some(12)
    );
    let mut c = NodeConfig::default();
    c.apply_kv("store_read_budget", "0").unwrap();
    assert_eq!(c.store_read_budget, Some(0));
    c.apply_kv("store_read_budget", "7").unwrap();
    assert_eq!(c.store_read_budget, Some(7));
    let bad = c.apply_kv("store_read_budget", "nope").unwrap_err();
    assert!(format!("{bad}").contains("store_read_budget"), "{bad}");
    let neg = c.apply_kv("store_read_budget", "-3").unwrap_err();
    assert!(format!("{neg}").contains("store_read_budget"), "{neg}");
    assert!(operator_config_from_args(
        ["rbitcoin-node", "--store-read-budget=-1"],
        &NodeEnv::default()
    )
    .is_err());
    let h = operator_usage();
    assert!(h.contains("--store-read-budget"), "{h}");
    assert!(
        h.contains("minimum 1"),
        "help must state the default formula: {h}"
    );
}
