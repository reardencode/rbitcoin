use rbitcoin_consensus::Milestone;
use rbitcoin_node::config::*;
use rbitcoin_primitives::Network;
use rbitcoin_store::HeadScale;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn tmp() -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("rbitcoin-node-cfg-{n}"))
}

#[test]
fn conf_error_names_the_file_and_line() {
    let dir = std::env::temp_dir().join(format!("rbitcoin-conf-line-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bad.conf");
    std::fs::write(&path, "secret-token-xyz\n").unwrap();
    let err = NodeConfig::default()
        .merge_conf_file(&path)
        .unwrap_err()
        .to_string();
    assert!(err.contains("bad.conf:1"), "{err}");
    assert!(err.contains("expected key=value"), "{err}");
    assert!(!err.contains("secret-token-xyz"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn check_blocks_apply_kv_zero_is_all() {
    let mut c = NodeConfig::default();
    assert_eq!(c.check_blocks, None);
    assert_eq!(c.check_blocks_window(), rbitcoin_store::VERIFY_TIP_BLOCKS);
    assert_eq!(c.apply_kv("check_blocks", "6").unwrap(), ConfApply::Applied);
    assert_eq!(c.check_blocks, Some(6));
    assert_eq!(c.check_blocks_window(), 6);
    assert_eq!(c.apply_kv("check-blocks", "0").unwrap(), ConfApply::Applied);
    assert_eq!(c.check_blocks, Some(0));
    assert_eq!(c.check_blocks_window(), 0);
    assert_eq!(
        c.apply_kv("check_blocks", "-1").unwrap(),
        ConfApply::Applied
    );
    assert_eq!(c.check_blocks, Some(-1));
    assert_eq!(c.check_blocks_window(), 0);
    let bad = c.apply_kv("check_blocks", "nope").unwrap_err();
    assert!(bad.to_string().contains("check-blocks"), "{bad}");
    assert_eq!(
        c.apply_kv("checkblocks", "6").unwrap(),
        ConfApply::Unknown("checkblocks".into())
    );
}

#[test]
fn prefillcompact_cli_conf_default_on() {
    let mut c = NodeConfig::default();
    assert!(c.prefill_compact);
    match c.apply_kv("prefillcompact", "0").unwrap() {
        ConfApply::Unknown(k) => assert_eq!(k, "prefillcompact"),
        other => panic!("{other:?}"),
    }
    assert!(c.prefill_compact);
    assert_eq!(
        c.apply_kv("prefill_compact", "0").unwrap(),
        ConfApply::Applied
    );
    assert!(!c.prefill_compact);
    assert_eq!(
        c.apply_kv("prefill_compact", "1").unwrap(),
        ConfApply::Applied
    );
    assert!(c.prefill_compact);
}

#[test]
fn tor_control_password_rejects_a_line_break() {
    let mut c = NodeConfig::default();
    let err = c
        .apply_kv("tor_control_password", "a\nb")
        .unwrap_err()
        .to_string();
    assert!(err.contains("CR"), "{err}");
    c.apply_kv("tor_control_password", "pw").unwrap();
    assert_eq!(c.tor.password.as_deref(), Some("pw"));
}

#[test]
fn apply_kv_is_the_conf_setter_and_unknown_is_not_error() {
    let mut c = NodeConfig::default();
    assert_eq!(
        c.apply_kv("network", "regtest").unwrap(),
        ConfApply::Applied
    );
    assert_eq!(c.network, Network::Regtest);
    assert_eq!(
        c.apply_kv("datadir", "/tmp/rb-apply-kv").unwrap(),
        ConfApply::Applied
    );
    assert_eq!(c.datadir.path(), Path::new("/tmp/rb-apply-kv"));
    match c.apply_kv("not-a-real-key", "1").unwrap() {
        ConfApply::Unknown(k) => assert_eq!(k, "not-a-real-key"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn rpc_socket_moves_the_socket_out_of_the_datadir() {
    let mut c = NodeConfig::default().with_datadir(Path::new("/var/lib/rbitcoin"));
    assert_eq!(c.rpc_socket_path(), Path::new("/var/lib/rbitcoin/rpc.sock"));
    assert_eq!(
        c.apply_kv("rpc_socket", "/run/rbitcoin/rpc.sock").unwrap(),
        ConfApply::Applied
    );
    assert!(c.rpc.socket, "rpc_socket implies rpc");
    assert_eq!(c.rpc_socket_path(), Path::new("/run/rbitcoin/rpc.sock"));
    let err = NodeConfig::default()
        .apply_kv("rpc_socket", "")
        .unwrap_err()
        .to_string();
    assert!(err.contains("rpc_socket requires a path"), "{err}");
}

#[test]
fn blocks_dir_is_not_an_operator_key() {
    let mut c = NodeConfig::default();
    assert_eq!(
        c.apply_kv("blocks_dir", "/tmp/x").unwrap(),
        ConfApply::Unknown("blocks_dir".into())
    );
    assert_eq!(
        c.apply_kv("blocks-dir", "/tmp/x").unwrap(),
        ConfApply::Unknown("blocks-dir".into())
    );
    assert_eq!(
        c.apply_kv("blocksdir", "/tmp/x").unwrap(),
        ConfApply::Unknown("blocksdir".into())
    );
}

#[test]
fn duplicate_listen_is_init_error() {
    let mut c = NodeConfig::default();
    assert_eq!(
        c.apply_kv("listen", "127.0.0.1:18444").unwrap(),
        ConfApply::Applied
    );
    let err = c.apply_kv("listen", "127.0.0.1:18444").unwrap_err();
    assert!(
        err.to_string().contains("Duplicate binding configuration"),
        "{err}"
    );
}

#[test]
fn sv2_tp_apply_kv_and_listen_requires_authority() {
    let mut c = NodeConfig::default().with_datadir(tmp());
    assert_eq!(c.sv2_tp_listen, None);
    assert_eq!(c.sv2_tp_cert_validity_secs, 3600);
    assert_eq!(c.sv2_tp_stale_grace, Duration::from_secs(10));
    assert_eq!(c.sv2_tp_fee_delta, 1000);
    assert_eq!(c.sv2_tp_template_interval, Duration::from_secs(5));
    for (k, v) in [
        ("sv2_tp_listen", "127.0.0.1:8442"),
        ("sv2_tp_cert_validity", "600"),
        ("sv2_tp_stale_grace", "0"),
        ("sv2_tp_fee_delta", "0"),
        ("sv2_tp_template_interval", "86400"),
    ] {
        assert_eq!(c.apply_kv(k, v).unwrap(), ConfApply::Applied);
    }
    assert_eq!(c.sv2_tp_listen, Some("127.0.0.1:8442".parse().unwrap()));
    assert_eq!(c.sv2_tp_cert_validity_secs, 600);
    assert_eq!(c.sv2_tp_stale_grace, Duration::ZERO);
    assert_eq!(c.sv2_tp_fee_delta, 0);
    assert_eq!(c.sv2_tp_template_interval, Duration::from_secs(86400));
    let no_auth = c.validate().unwrap_err();
    assert!(
        format!("{no_auth}").contains("sv2-tp-authority-sec"),
        "{no_auth}"
    );
    assert_eq!(
        c.apply_kv("sv2_tp_authority_sec", &"07".repeat(32))
            .unwrap(),
        ConfApply::Applied
    );
    assert_eq!(c.sv2_tp_authority_sec, Some(Sv2AuthoritySecret([7; 32])));
    assert!(c.validate().is_ok());

    let zero = "00".repeat(32);
    let not_hex = "zz".repeat(32);
    for (k, v) in [
        ("sv2_tp_listen", "nope"),
        ("sv2_tp_authority_sec", "07"),
        ("sv2_tp_authority_sec", zero.as_str()),
        ("sv2_tp_authority_sec", not_hex.as_str()),
        ("sv2_tp_cert_validity", "0"),
        ("sv2_tp_stale_grace", "-1"),
        ("sv2_tp_stale_grace", "86401"),
        ("sv2_tp_cert_validity", "4294967296"),
        ("sv2_tp_fee_delta", "-1"),
        ("sv2_tp_template_interval", "0"),
        ("sv2_tp_template_interval", "86401"),
    ] {
        let e = format!("{}", c.apply_kv(k, v).unwrap_err());
        assert!(e.contains(k), "garbage must name the knob: {e}");
    }
}

#[test]
fn sv2_tp_authority_sec_file_reads_the_key_off_argv() {
    let dir = tmp();
    std::fs::create_dir_all(&dir).unwrap();
    let mut c = NodeConfig::default().with_datadir(dir.clone());
    let key = dir.join("sv2-authority.key");
    std::fs::write(&key, format!("{}\n", "07".repeat(32))).unwrap();
    let path = key.to_str().unwrap();
    assert_eq!(
        c.apply_kv("sv2_tp_authority_sec_file", path).unwrap(),
        ConfApply::Applied
    );
    assert_eq!(c.sv2_tp_authority_sec, Some(Sv2AuthoritySecret([7; 32])));

    let bad = dir.join("sv2-bad.key");
    std::fs::write(&bad, "00".repeat(32)).unwrap();
    let missing = dir.join("sv2-missing.key");
    for p in [&bad, &missing] {
        let e = format!(
            "{}",
            c.apply_kv("sv2_tp_authority_sec_file", p.to_str().unwrap())
                .unwrap_err()
        );
        assert!(e.contains("sv2_tp_authority_sec_file"), "{e}");
        assert!(!e.contains(&"00".repeat(32)), "never echo the key: {e}");
    }
}

/// An operator who passes the key itself to the file knob, or logs the
/// config, must not see the key printed.
#[test]
fn sv2_tp_authority_secret_never_prints() {
    let hex = "07".repeat(32);
    let mut c = NodeConfig::default();
    c.apply_kv("sv2_tp_authority_sec", &hex).unwrap();
    let dbg = format!("{c:?}");
    assert!(dbg.contains("sv2_tp_authority_sec"), "{dbg}");
    assert!(!dbg.contains("[7, 7"), "never print the key: {dbg}");
    assert!(!dbg.contains(&hex), "never print the key: {dbg}");

    let e = format!(
        "{}",
        c.apply_kv("sv2_tp_authority_sec_file", &hex).unwrap_err()
    );
    assert!(e.contains("sv2_tp_authority_sec_file"), "{e}");
    assert!(!e.contains(&hex), "never echo the key: {e}");
}

/// key-utils 1.2.0 vector: SRI configs carry the authority secret as
/// `Secp256k1SecretKey` base58check; its pubkey is the one the TP prints.
#[test]
fn sv2_tp_authority_sec_takes_key_utils_base58check() {
    let secret = "zmBEmPhqo3A92FkiLVvyCz6htc3e53ph3ZbD4ASqGaLjwnFLi";
    let dir = tmp();
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("sv2-authority.key");
    std::fs::write(&file, format!("{secret}\n")).unwrap();
    for (k, v) in [
        ("sv2_tp_authority_sec", secret),
        ("sv2_tp_authority_sec_file", file.to_str().unwrap()),
    ] {
        let mut c = NodeConfig::default().with_datadir(dir.clone());
        assert_eq!(c.apply_kv(k, v).unwrap(), ConfApply::Applied);
        let kp = bitcoin::secp256k1::Keypair::from_seckey_slice(
            &bitcoin::secp256k1::Secp256k1::new(),
            &c.sv2_tp_authority_sec.unwrap().0,
        )
        .unwrap();
        let mut pk = vec![1, 0];
        pk.extend(kp.x_only_public_key().0.serialize());
        assert_eq!(
            bitcoin::base58::encode_check(&pk),
            "9bDuixKmZqAJnrmP746n8zU1wyAQRrus7th9dxnkPg6RzQvCnan"
        );
    }
    let mut c = NodeConfig::default();
    let bad_check = format!("{}1", &secret[..secret.len() - 1]);
    let e = format!(
        "{}",
        c.apply_kv("sv2_tp_authority_sec", &bad_check).unwrap_err()
    );
    assert!(e.contains("sv2_tp_authority_sec"), "{e}");
    assert!(!e.contains(&bad_check), "never echo the key: {e}");
}

#[test]
fn max_sh_creates_and_esplora_block_template_apply_kv() {
    let mut c = NodeConfig::default();
    assert_eq!(c.max_sh_creates, rbitcoin_query::DEFAULT_MAX_SH_CREATES);
    assert!(!c.esplora_block_template);
    assert_eq!(
        c.apply_kv("max_sh_creates", "100").unwrap(),
        ConfApply::Applied
    );
    assert_eq!(c.max_sh_creates, 100);
    match c.apply_kv("maxshcreates", "7").unwrap() {
        ConfApply::Unknown(k) => assert_eq!(k, "maxshcreates"),
        other => panic!("{other:?}"),
    }
    assert_eq!(c.apply_kv("sh_index", "1").unwrap(), ConfApply::Applied);
    assert!(c.shindex);
    assert_eq!(c.apply_kv("sp_tweaks", "1").unwrap(), ConfApply::Applied);
    assert!(c.sptweaks);
    assert_eq!(
        c.apply_kv("sp_tweaks_dust", "546").unwrap(),
        ConfApply::Applied
    );
    assert_eq!(c.sptweaks_dust, 546);
    assert_eq!(c.max_sh_creates, 100);
    assert_eq!(
        c.apply_kv("heavy_sh_creates", "250").unwrap(),
        ConfApply::Applied
    );
    assert_eq!(c.heavy_sh_creates, 250);
    let bad = c.apply_kv("heavy_sh_creates", "nope").unwrap_err();
    assert!(format!("{bad}").contains("heavy_sh_creates"), "{bad}");
    let bad = c.apply_kv("max_sh_creates", "nope").unwrap_err();
    assert!(
        format!("{bad}").contains("max_sh_creates"),
        "garbage must name the knob: {bad}"
    );
    assert_eq!(
        c.apply_kv("esplora_block_template", "1").unwrap(),
        ConfApply::Applied
    );
    assert!(c.esplora_block_template);
    match c.apply_kv("esplorablocktemplate", "0").unwrap() {
        ConfApply::Unknown(k) => assert_eq!(k, "esplorablocktemplate"),
        other => panic!("{other:?}"),
    }
    assert!(c.esplora_block_template);
}

#[test]
fn concatenated_index_conf_keys_are_unknown() {
    let mut c = NodeConfig::default();
    match c.apply_kv("shindex", "1").unwrap() {
        ConfApply::Unknown(k) => assert_eq!(k, "shindex"),
        other => panic!("{other:?}"),
    }
    match c.apply_kv("sptweaks", "1").unwrap() {
        ConfApply::Unknown(k) => assert_eq!(k, "sptweaks"),
        other => panic!("{other:?}"),
    }
    match c.apply_kv("sptweaks_dust", "1").unwrap() {
        ConfApply::Unknown(k) => assert_eq!(k, "sptweaks_dust"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn whitelist_parse_errors_match_core() {
    let mut c = NodeConfig::default();
    let err = c
        .apply_kv("net-permission", "in,out@127.0.0.1")
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("Only direction was set, no permissions"),
        "{err}"
    );
    let err = c
        .apply_kv("net-permission", "oopsie@127.0.0.1")
        .unwrap_err();
    assert!(err.to_string().contains("Invalid P2P permission"), "{err}");
    let err = c
        .apply_kv("net-permission", "noban@127.0.0.1:230")
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("Invalid netmask specified in --net-permission"),
        "{err}"
    );
    let err = c
        .apply_kv("net-permission-bind", "noban@127.0.0.1/10")
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("Cannot resolve --net-permission-bind address"),
        "{err}"
    );
    assert_eq!(
        c.apply_kv("net-permission", "127.0.0.1").unwrap(),
        ConfApply::Applied
    );
    let t = c.finalized_net_perms();
    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let bind = "127.0.0.1:18444".parse().unwrap();
    assert_eq!(
        t.strings_for(ip, true, bind),
        ["noban", "relay", "mempool", "download"]
    );
    c.net_permission_relay = false;
    let t = c.finalized_net_perms();
    assert_eq!(
        t.strings_for(ip, true, bind),
        ["noban", "mempool", "download"]
    );
    let mut c2 = NodeConfig::default();
    c2.apply_kv("net-permission-bind", "noban@127.0.0.1:18445")
        .unwrap();
    assert_eq!(
        c2.listen.p2p,
        P2pListen::Socket("127.0.0.1:18445".parse().unwrap()),
        "net_permission_bind listens"
    );
    assert_eq!(c2.net_perms.whitebind.len(), 1);
}

#[test]
fn default_datadir_is_native_cwd_relative() {
    let p = NodeConfig::default_datadir();
    assert_eq!(p, PathBuf::from(".").join("datadir"));
    assert_eq!(NodeConfig::default().datadir.path(), p.as_path());
    let store = p.join("store");
    #[cfg(windows)]
    {
        let s = store.to_string_lossy();
        assert!(
            !s.contains('/'),
            "default datadir must use Windows separators, got {s}"
        );
        assert_eq!(p.to_str(), Some(r".\datadir"));
    }
    #[cfg(not(windows))]
    {
        assert_eq!(p.to_str(), Some("./datadir"));
        assert_eq!(store.to_str(), Some("./datadir/store"));
    }
}

#[test]
fn store_layout_default_is_mainnet_tiny_builder_is_tiny() {
    let mainnet = NodeConfig::default();
    assert_eq!(mainnet.head_scale, HeadScale::Mainnet);
    assert_eq!(mainnet.store_layout().head_scale, HeadScale::Mainnet);
    assert_eq!(mainnet.store_layout().header_slots(), 1 << 22);
    assert_eq!(mainnet.store_layout().sh_shard_count(), 64);
    // Do not create those files in the default suite.

    let tiny = NodeConfig::default().with_tiny_heads();
    assert_eq!(tiny.head_scale, HeadScale::Tiny);
    assert_eq!(tiny.store_layout().head_scale, HeadScale::Tiny);
    assert_eq!(tiny.store_layout().header_slots(), 64);
    assert_eq!(tiny.store_layout().sh_shard_count(), 1);

    let dir = tmp();
    let mut split = NodeConfig::default().with_datadir(&dir).with_tiny_heads();
    split.datadir.cold = Some(dir.join("cold"));
    assert_eq!(split.store_layout().head_scale, HeadScale::Tiny);
    assert_eq!(
        split.store_layout().cold_dir.as_deref(),
        Some(dir.join("cold").join("store").as_path())
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn builders_paths_milestone_and_ensure() {
    let dir = tmp();
    let cfg = NodeConfig::default()
        .with_datadir(&dir)
        .with_network(Network::Regtest)
        .with_p2p_listen("127.0.0.1:0".parse().unwrap());
    assert_eq!(cfg.network, Network::Regtest);
    assert_eq!(cfg.store_path(), dir.join("store"));
    assert_eq!(cfg.store_cold_path(), None);
    assert_eq!(cfg.mempool_path(), dir.join("mempool"));
    assert_eq!(cfg.listen.max_inbound, DEFAULT_MAX_INBOUND);
    assert!(!cfg.listen.max_inbound_explicit);
    cfg.ensure_datadir().unwrap();
    assert!(dir.join("store").is_dir());
    assert!(dir.join("mempool").is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        extern "C" {
            fn umask(mask: u32) -> u32;
        }
        let fresh = dir.join("umask-fresh");
        let _ = std::fs::remove_dir_all(&fresh);
        // SAFETY: `umask` is process-global. This test restores `prev` before the asserts.
        let prev = unsafe { umask(0o022) };
        let created = NodeConfig::default().with_datadir(&fresh).with_tiny_heads();
        created.ensure_datadir().unwrap();
        let mode = std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777;
        std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o755)).unwrap();
        created.ensure_datadir().unwrap();
        let kept = std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777;
        // SAFETY: restores the umask saved above.
        unsafe { umask(prev) };
        assert_eq!(mode, 0o700, "new datadir under umask 0022 is {mode:o}");
        assert_eq!(
            kept, 0o755,
            "an existing datadir is not chmodded, got {kept:o}"
        );
        let _ = std::fs::remove_dir_all(&fresh);
    }
    cfg.ensure_datadir().unwrap();
    let cold = dir.join("cold");
    let mut split = NodeConfig::default().with_datadir(&dir);
    split.datadir.cold = Some(cold.clone());
    assert_eq!(
        split.store_cold_path().as_deref(),
        Some(cold.join("store").as_path())
    );
    split.ensure_datadir().unwrap();
    assert!(cold.join("store").is_dir());
    let mut same = NodeConfig::default().with_datadir(&dir);
    same.datadir.cold = Some(dir.clone());
    assert!(same.validate().unwrap_err().to_string().contains("differ"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Env is an input when inbound was not explicit; never published back.
#[test]
fn absorb_inbound_env_reads_but_does_not_write() {
    let _g = OPERATOR_ENV_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let prev_in = std::env::var_os("RBITCOIN_P2P_MAX_INBOUND");
    std::env::set_var("RBITCOIN_P2P_MAX_INBOUND", "99");
    let mut cfg = NodeConfig::default();
    assert!(!cfg.listen.max_inbound_explicit);
    cfg.absorb_inbound_env();
    assert_eq!(cfg.listen.max_inbound, 99);
    assert_eq!(
        std::env::var("RBITCOIN_P2P_MAX_INBOUND").as_deref(),
        Ok("99"),
        "absorb must not rewrite process env"
    );
    let mut explicit = NodeConfig::default();
    explicit.listen.max_inbound = 12;
    explicit.listen.max_inbound_explicit = true;
    explicit.absorb_inbound_env();
    assert_eq!(
        explicit.listen.max_inbound, 12,
        "explicit CLI/conf wins over env"
    );
    match prev_in {
        Some(v) => std::env::set_var("RBITCOIN_P2P_MAX_INBOUND", v),
        None => std::env::remove_var("RBITCOIN_P2P_MAX_INBOUND"),
    }
}

#[test]
fn operator_knob_defaults_and_fields() {
    let mut cfg = NodeConfig::default();
    cfg.listen.max_inbound = 42;
    cfg.listen.max_inbound_explicit = true;
    assert_eq!(cfg.listen.max_inbound, 42);
    assert_eq!(
        NodeConfig::default().listen.max_inbound,
        DEFAULT_MAX_INBOUND
    );
}

#[test]
fn max_inbound_conf_is_explicit_not_core_total_slots() {
    let dir = tmp();
    std::fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("mi.conf");
    std::fs::write(&conf, "max_inbound=40\n").unwrap();
    let mut cfg = NodeConfig::default().with_datadir(dir.join("d"));
    cfg.merge_conf_file(&conf).unwrap();
    assert_eq!(cfg.listen.max_inbound, 40);
    assert!(cfg.listen.max_inbound_explicit);

    let conf2 = dir.join("mc.conf");
    std::fs::write(&conf2, "maxconnections=32\n").unwrap();
    let mut cfg2 = NodeConfig::default().with_datadir(dir.join("d2"));
    cfg2.merge_conf_file(&conf2).unwrap();
    assert_eq!(
        cfg2.listen.max_inbound, DEFAULT_MAX_INBOUND,
        "Core maxconnections is unknown on the node (shim-only)"
    );
    assert!(!cfg2.listen.max_inbound_explicit);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn native_permission_and_ibd_knobs_apply() {
    let mut cfg = NodeConfig::default();
    assert_eq!(cfg.apply_kv("trusted", "1").unwrap(), ConfApply::Applied);
    assert!(cfg.trusted);
    assert_eq!(
        cfg.apply_kv("always-relay", "1").unwrap(),
        ConfApply::Applied
    );
    assert!(cfg.always_relay);
    assert_eq!(cfg.apply_kv("relay", "1").unwrap(), ConfApply::Applied);
    assert!(cfg.relay);
    assert_eq!(
        cfg.apply_kv("min-chain-work", "0x65").unwrap(),
        ConfApply::Applied
    );
    assert!(cfg.minimum_chain_work.is_some());
    assert_eq!(
        cfg.apply_kv("max-tip-age", "3600").unwrap(),
        ConfApply::Applied
    );
    assert_eq!(cfg.max_tip_age_secs, Some(3600));
    assert_eq!(
        cfg.apply_kv("blocks-only", "1").unwrap(),
        ConfApply::Applied
    );
    assert!(cfg.mempool.blocksonly);
    assert_eq!(cfg.apply_kv("ua-comment", "x").unwrap(), ConfApply::Applied);
    assert_eq!(cfg.uacomments.as_slice(), ["x"]);
    assert_eq!(
        cfg.apply_kv("chain", "regtest").unwrap(),
        ConfApply::Unknown("chain".into())
    );
    assert_eq!(
        cfg.apply_kv("whitelist", "noban@127.0.0.1").unwrap(),
        ConfApply::Unknown("whitelist".into())
    );
    assert_eq!(
        cfg.apply_kv("maxconnections", "32").unwrap(),
        ConfApply::Unknown("maxconnections".into())
    );
    assert_eq!(
        cfg.apply_kv("assumevalid_height", "0").unwrap(),
        ConfApply::Unknown("assumevalid_height".into())
    );
}

#[test]
fn ensure_datadir_rejects_file_path_after_parent_exists() {
    let dir = tmp();
    std::fs::create_dir_all(&dir).unwrap();
    let file_as_dir = dir.join("notadir");
    std::fs::write(&file_as_dir, b"x").unwrap();
    let cfg = NodeConfig::default().with_datadir(&file_as_dir);
    assert!(cfg.ensure_datadir().is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ensure_datadir_rejects_file_as_subdir() {
    let dir = tmp();
    let cfg = NodeConfig::default().with_datadir(&dir);
    cfg.ensure_datadir().unwrap();
    // Make store a file so recreate fails.
    let _ = std::fs::remove_dir_all(dir.join("store"));
    std::fs::write(dir.join("store"), b"x").unwrap();
    let err = cfg.ensure_datadir().unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("store") || msg.contains("datadir") || msg.contains("File exists"),
        "{msg}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn validate_checks_rpc_cookie_at_startup() {
    let dir = tmp();
    std::fs::create_dir_all(&dir).unwrap();
    let cookie = dir.join("rpc.cookie");
    let mut cfg = NodeConfig::default().with_datadir(dir.clone());
    cfg.rpc.cookie_file = Some(cookie.clone());
    cfg.rpc.listen_default = true;
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("read RPC cookie"), "missing file: {err}");
    std::fs::write(&cookie, "__cookie__:secret\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cookie, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("line ending"), "{err}");
    std::fs::write(&cookie, "__cookie__:secret").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cookie, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("--rpc-cookie-perms owner"), "{err}");
        std::fs::set_permissions(&cookie, std::fs::Permissions::from_mode(0o640)).unwrap();
        cfg.rpc.cookie_perms = rbitcoin_rpc::RpcCookiePerms::Group;
        cfg.validate()
            .expect("0640 is within --rpc-cookie-perms group");
        std::fs::set_permissions(&cookie, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("--rpc-cookie-perms group"), "{err}");
        std::fs::set_permissions(&cookie, std::fs::Permissions::from_mode(0o660)).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("--rpc-cookie-perms group"), "{err}");
        cfg.rpc.cookie_perms = rbitcoin_rpc::RpcCookiePerms::All;
        std::fs::set_permissions(&cookie, std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("--rpc-cookie-perms all"), "{err}");
        std::fs::set_permissions(&cookie, std::fs::Permissions::from_mode(0o644)).unwrap();
        cfg.validate()
            .expect("0644 is within --rpc-cookie-perms all");
        std::fs::set_permissions(&cookie, std::fs::Permissions::from_mode(0o600)).unwrap();
        cfg.rpc.cookie_perms = rbitcoin_rpc::RpcCookiePerms::Owner;
    }
    cfg.validate()
        .expect("Core-format cookie with --rpc-listen");
    cfg.rpc.listen_default = false;
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("TCP only"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn validate_rejects_zero_peer_caps_and_empty_datadir() {
    let mut cfg = NodeConfig::default();
    cfg.datadir.path = PathBuf::new();
    assert!(cfg.validate().is_err());
    let mut cfg = NodeConfig::default().with_datadir(tmp());
    cfg.listen.max_outbound = 0;
    assert!(cfg.validate().is_err());
    cfg.listen.max_outbound = 1;
    cfg.listen.max_inbound = 0;
    assert!(cfg.validate().is_ok());
    assert_eq!(cfg.milestone(), Milestone::NONE);
    cfg.milestone_height = 10;
    assert_eq!(cfg.milestone().height, 10);
}

#[test]
fn conf_keys_parse_and_error_paths() {
    let dir = tmp();
    std::fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("full.conf");
    std::fs::write(
        &conf,
        "listen=127.0.0.1:18444\n\
         connect=127.0.0.1:18445\n\
         sh_index=1\n\
         electrum_listen=127.0.0.1:50001\n\
         esplora_listen=127.0.0.1:3000\n\
         rpc_listen=127.0.0.1:8332\n\
         milestone=100\n\
         max_outbound=8\n\
         max_inbound=32\n\
         mempool_size_mb=50\n\
         log_level=info\n\
         no_seeds=0\n\
         unknown_key=1\n\
         network=regtest\n",
    )
    .unwrap();
    let mut cfg = NodeConfig::default().with_datadir(dir.join("d"));
    cfg.merge_conf_file(&conf).unwrap();
    assert_eq!(cfg.network, Network::Regtest);
    assert!(matches!(cfg.listen.p2p, P2pListen::Socket(_)));
    assert_eq!(cfg.listen.connect.len(), 1);
    assert!(cfg.shindex);
    assert!(!cfg.sptweaks);
    assert!(cfg.listen.electrum.is_some());
    assert!(cfg.listen.esplora.is_some());
    assert!(cfg.rpc.listen.is_some());
    assert_eq!(cfg.milestone_height, 100);
    assert_eq!(cfg.listen.max_outbound, 8);
    assert_eq!(cfg.listen.max_inbound, 32);
    assert!(cfg.listen.max_inbound_explicit);
    assert_eq!(cfg.mempool.max_weight, 50_000_000);
    assert_eq!(cfg.conf_log_level.as_deref(), Some("info"));
    assert!(cfg.listen.use_seeds); // no_seeds=0 → seeds on

    for (body, needle) in [
        ("listen=not-an-addr\n", "listen"),
        ("electrum_listen=bad\n", "electrum"),
        ("esplora_listen=bad\n", "esplora"),
        ("health_listen=bad\n", "health"),
        ("mempool_size_mb=0\n", "mempool"),
        ("log_level=\n", "log_level"),
        ("network=notanet\n", "network"),
        ("milestone=x\n", "milestone"),
    ] {
        let p = dir.join(format!("bad-{needle}.conf"));
        std::fs::write(&p, body).unwrap();
        let mut c = NodeConfig::default().with_datadir(dir.join("dx"));
        let err = c.merge_conf_file(&p).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.to_ascii_lowercase().contains(needle)
                || msg.contains("conf")
                || msg.contains("parse"),
            "body={body:?} msg={msg}"
        );
    }

    let file_dd = dir.join("not-a-dir");
    std::fs::write(&file_dd, b"x").unwrap();
    let cfg_f = NodeConfig::default().with_datadir(&file_dd);
    assert!(cfg_f.ensure_datadir().is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn testactivationheight_csv_overlay_on_chain_params() {
    let mut cfg = NodeConfig::default();
    cfg.network = Network::Regtest;
    cfg.test_activation_heights.push(("csv".into(), 102));
    let p = cfg.chain_params().unwrap();
    assert_eq!(p.csv_height(), 102);
    assert!(!p.csv_active_at(101));
    assert!(p.csv_active_at(102));
    let plain = NodeConfig::default();
    assert!(plain.mempool.persist);
    assert!(!plain.mempool.blocksonly);
    assert!(plain.prefill_compact);
    assert!(plain.test_activation_heights.is_empty());
    assert_eq!(
        {
            let mut cfg = NodeConfig::default();
            cfg.network = Network::Regtest;
            cfg
        }
        .chain_params()
        .unwrap()
        .csv_height(),
        1
    );
}

#[test]
fn connect_hostname_is_dns_not_netaddr() {
    let mut cfg = NodeConfig::default();
    cfg.apply_kv("head_scale", "tiny").unwrap();
    assert_eq!(cfg.head_scale, HeadScale::Tiny);
    cfg.apply_kv("connect", "tank-0001:18444").unwrap();
    cfg.apply_kv("connect", "bad").unwrap();
    cfg.apply_kv("connect", "tank-0").unwrap();
    cfg.apply_kv("connect", "127.0.0.1:18444").unwrap();
    assert!(cfg
        .listen
        .connect_dns
        .iter()
        .any(|h| h == "tank-0001:18444"));
    assert!(cfg.listen.connect_dns.iter().any(|h| h == "bad"));
    assert!(cfg.listen.connect_dns.iter().any(|h| h == "tank-0"));
    assert_eq!(cfg.listen.connect.len(), 1);
    assert!(cfg.apply_kv("connect", "").is_err());
    assert!(cfg
        .apply_kv("connect", "short.onion:8333")
        .unwrap_err()
        .to_string()
        .contains("bad"));
    assert!(cfg.listen.has_pinned_connect());
}
