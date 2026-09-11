use crate::config::{ConfApply, NodeConfig};
use crate::inhibit::SuspendInhibit;
use crate::run::{run_node, run_p2p};
use rbitcoin_consensus::default_milestone_height;
use rbitcoin_log::{self, error, info, warn, Level};
use rbitcoin_store::HeadScale;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

/// CLI parse result before log init / datadir open / run.
#[derive(Debug)]
pub(crate) enum OperatorArgs {
    Help,
    Version,
    Ready {
        config: NodeConfig,
        log_level_cli: Option<Option<Level>>,
    },
}

/// Assemble [`NodeConfig`] from argv (conf then CLI `apply_kv`). Does not open the store.
pub(crate) fn operator_config_from_args<I, T>(args: I) -> Result<OperatorArgs, ExitCode>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let mut i = 1usize;
    let mut smoke = false;
    let mut conf_path: Option<PathBuf> = None;
    let mut log_level_cli: Option<Option<Level>> = None;
    let mut kvs: Vec<(String, String)> = Vec::new();

    while i < args.len() {
        let a = args[i].to_string_lossy();
        match a.as_ref() {
            "--help" | "-h" => {
                eprintln!(
                    "rbitcoin-node {} — usage:\n\
  rbitcoin-node [--conf FILE] [--datadir PATH] [--datadir-cold PATH] [--network NET] \\\n\
    [--listen ADDR] [--connect ADDR]... [--electrum-listen ADDR] [--esplora-listen ADDR] \\\n\
    [--shindex] [--sptweaks] [--sptweaks-dust SATS] [--rpc-listen ADDR] [--rpcuser USER] [--rpcpassword PASS] \\\n\
    [--milestone|--assumevalid-height HEIGHT] \\\n\
    [--maxoutbound|--max-outbound N] [--maxinbound N] [--maxconnections N] \\\n\
    [--mempool-size-mb|--maxmempool N] \\\n\
    [--testactivationheight name@height] [--persistmempool[=0|1]] [--whitelist SPEC] \\\n\
    [--blocksonly] [--minrelaytxfee BTC] [--permitbaremultisig[=0|1]] \\\n\
    [--limitclustercount N] [--limitclustersize KVB] [--peertimeout SECS] \\\n\
    [--externalip IP] \\\n\
    [--minimumchainwork HEX] \\\n\
    [--max-run-secs N] [--log-level LEVEL] [--api-log PATH] [--asmap PATH] [--uacomment STR] \\\n\
    [--no-seeds] [--smoke] [--inhibit-suspend]\n\n\
Networks: mainnet|testnet|signet|regtest\n\
Custom Signet: --signetchallenge HEX [--signetblocktime SECONDS].\n\
Log level: error|warn|info|debug|trace|off (CLI > conf log_level > RBITCOIN_LOG / RUST_LOG).\n\
API log: --api-log PATH writes one JSON line per Electrum/Esplora/RPC call (also TRACE `api:`).\n\
Asmap: --asmap PATH loads a Core ip_asn.dat (relative to datadir). Unset tries {{datadir}}/ip_asn.dat.\n\
Milestone / assumevalid-height: skip script/sig checks at/below HEIGHT.\n\
  Defaults: mainnet 840000, signet 2000000, testnet 2500000, regtest 0. Use 0 for full scripts.\n\
Mempool: --mempool-size-mb / --maxmempool (default ~300 MiB weight budget).\n\
Peers: --maxoutbound (default 16 live download), --maxinbound (default 125), --maxconnections Core total (inbound = N-11).\n\
Scripthash: --shindex (default off) builds Class B for Electrum/Esplora; both require it.\n\
Silent payments: --sptweaks (default off) writes/serves the thin BIP-352 tweak index.\n\
  --sptweaks-dust SATS omits served P2TR outs with value <= SATS (default 1000; 0 = all; 546 = Cake electrs).\n\
RPC: --rpc-listen ADDR (default off); cookie under datadir/.cookie or --rpcuser/--rpcpassword.\n\
Cold files: --datadir-cold PATH puts Class A inwit.body/idx under PATH/store (HDD).\n\
  Default (flag omitted): hot and cold files both live under --datadir.\n\
Conf: --conf FILE (key=value; CLI overrides conf). See OPERATOR.md and docs/rpc.md.\n\
Advanced debug/IO knobs remain RBITCOIN_* env (not required for normal sync; preserved if CLI omits).\n\
IBD: up to 1024 concurrent getdata, max 16 in transit per peer.",
                    env!("CARGO_PKG_VERSION")
                );
                return Ok(OperatorArgs::Help);
            }
            "--version" | "-V" => {
                eprintln!("rbitcoin-node {}", env!("CARGO_PKG_VERSION"));
                return Ok(OperatorArgs::Version);
            }
            "--smoke" => {
                smoke = true;
                i += 1;
            }
            "--conf" => match take_arg(&args, &mut i, "--conf") {
                Ok(v) => conf_path = Some(PathBuf::from(v)),
                Err(c) => return Err(c),
            },
            other if other.starts_with("--conf=") => {
                let v = &other["--conf=".len()..];
                if v.is_empty() {
                    eprintln!("error: --conf requires a path");
                    return Err(ExitCode::from(2));
                }
                conf_path = Some(PathBuf::from(v));
                i += 1;
            }
            "--log-level" => match take_arg(&args, &mut i, "--log-level") {
                Ok(raw) => match parse_log_level(&raw) {
                    Ok(v) => log_level_cli = Some(v),
                    Err(c) => return Err(c),
                },
                Err(c) => return Err(c),
            },
            other if other.starts_with("--log-level=") => {
                match parse_log_level(&other["--log-level=".len()..]) {
                    Ok(v) => log_level_cli = Some(v),
                    Err(c) => return Err(c),
                }
                i += 1;
            }
            other => match parse_cli_flag(&args, &mut i, other) {
                Ok(Some(kv)) => kvs.push(kv),
                Ok(None) => {}
                Err(c) => return Err(c),
            },
        }
    }

    let mut config = NodeConfig::default();
    if let Some(ref cp) = conf_path {
        if let Err(e) = config.merge_conf_file(cp) {
            eprintln!("error: {e}");
            return Err(ExitCode::from(2));
        }
        config.conf_path = Some(cp.clone());
    }

    let mut saw_listen = false;
    let mut saw_connect = false;
    let mut saw_seednode = false;
    for (key, val) in kvs {
        if key == "listen" && !saw_listen {
            config.listen.p2p = None;
            config.listen.p2p_extra.clear();
            saw_listen = true;
        }
        if key == "connect" && !saw_connect {
            config.listen.connect.clear();
            saw_connect = true;
        }
        if key == "seednode" && !saw_seednode {
            config.listen.seednodes.clear();
            saw_seednode = true;
        }
        match config.apply_kv(&key, &val) {
            Ok(ConfApply::Applied) => {}
            Ok(ConfApply::Unknown(k)) => {
                eprintln!("error: unknown argument `--{k}`");
                return Err(ExitCode::from(2));
            }
            Err(e) => return Err(cli_apply_err(e)),
        }
    }

    if let Err(e) =
        rbitcoin_primitives::rbitcoin_subversion(env!("CARGO_PKG_VERSION"), &config.uacomments)
    {
        eprintln!("{e}");
        return Err(ExitCode::from(1));
    }

    if !config.milestone_explicit {
        config.milestone_height = default_milestone_height(config.network);
    }
    config.smoke = smoke;
    config.absorb_inbound_env();
    Ok(OperatorArgs::Ready {
        config,
        log_level_cli,
    })
}

/// Process entry used by `main` and high-level scenarios.
pub fn cli_main<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let (mut config, log_level_cli) = match operator_config_from_args(args) {
        Ok(OperatorArgs::Help | OperatorArgs::Version) => return ExitCode::SUCCESS,
        Ok(OperatorArgs::Ready {
            config,
            log_level_cli,
        }) => (config, log_level_cli),
        Err(c) => return c,
    };

    match log_level_cli {
        Some(Some(level)) => rbitcoin_log::init(level),
        Some(None) => rbitcoin_log::init_off(),
        None => {
            if let Some(ref raw) = config.conf_log_level {
                match parse_log_level(raw) {
                    Ok(Some(l)) => rbitcoin_log::init(l),
                    Ok(None) => rbitcoin_log::init_off(),
                    Err(c) => return c,
                }
            } else if !rbitcoin_log::init_from_env() {
                rbitcoin_log::init(Level::Info);
            }
        }
    }

    if let Some(ref p) = config.api_log {
        if let Err(e) = rbitcoin_log::init_api_log(p) {
            eprintln!("error: --api-log {}: {e}", p.display());
            return ExitCode::from(2);
        }
        rbitcoin_log::info!("api-log: {}", p.display());
    }

    let (soft, hard) = rbitcoin_store::ensure_nofile_budget();
    if soft > 0 {
        rbitcoin_log::debug!("node: RLIMIT_NOFILE soft={soft} hard={hard}");
    }

    let _suspend_inhibit = if config.inhibit_suspend {
        match SuspendInhibit::try_start("rbitcoin-node running (IBD / tip follow)") {
            Some(g) => Some(g),
            None => {
                warn!(
                    "node: --inhibit-suspend requested but systemd-inhibit unavailable; continuing without inhibit"
                );
                None
            }
        }
    } else {
        None
    };

    if let Err(e) = config.ensure_datadir() {
        error!("{e}");
        return ExitCode::FAILURE;
    }

    if config.smoke {
        config.head_scale = HeadScale::Tiny;
        match run_node(config) {
            Ok(handle) => {
                info!(
                    "rbitcoin-node {} on {} datadir={}",
                    env!("CARGO_PKG_VERSION"),
                    handle.network_name(),
                    handle.config.datadir.path().display()
                );
                if std::env::var_os("RBITCOIN_TEST_DROP_STORE").is_some() {
                    let _ = std::fs::remove_dir_all(handle.config.store_path());
                }
                match handle.shutdown() {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        error!("shutdown error: {e}");
                        ExitCode::FAILURE
                    }
                }
            }
            Err(e) => {
                error!("{e}");
                ExitCode::FAILURE
            }
        }
    } else {
        let rt = match node_tokio_runtime() {
            Ok(rt) => rt,
            Err(e) => {
                error!("runtime: {e}");
                return ExitCode::FAILURE;
            }
        };
        let code = match rt.block_on(run_p2p(config)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                if matches!(e, crate::error::NodeError::FutureTip) {
                    eprintln!("{e}");
                } else {
                    error!("{e}");
                }
                ExitCode::FAILURE
            }
        };
        rt.shutdown_timeout(std::time::Duration::from_secs(2));
        code
    }
}

fn take_arg(args: &[OsString], i: &mut usize, flag: &str) -> Result<String, ExitCode> {
    *i += 1;
    if *i >= args.len() {
        eprintln!("error: {flag} requires a value");
        return Err(ExitCode::from(2));
    }
    let v = args[*i].to_string_lossy().into_owned();
    *i += 1;
    Ok(v)
}

fn parse_log_level(raw: &str) -> Result<Option<Level>, ExitCode> {
    if raw.eq_ignore_ascii_case("off") || raw.eq_ignore_ascii_case("none") {
        Ok(None)
    } else if let Some(l) = Level::parse(raw) {
        Ok(Some(l))
    } else {
        eprintln!("error: bad --log-level `{raw}` (use error|warn|info|debug|trace|off)");
        Err(ExitCode::from(2))
    }
}

fn is_bool_key(key: &str) -> bool {
    matches!(
        key,
        "shindex"
            | "sptweaks"
            | "blocksonly"
            | "blocks_only"
            | "persistmempool"
            | "persist_mempool"
            | "permitbaremultisig"
            | "permit_bare_multisig"
            | "noseeds"
            | "no_seeds"
            | "inhibit_suspend"
            | "inhibitsuspend"
    )
}

fn looks_like_flag(s: &str) -> bool {
    s.starts_with("--") || matches!(s, "-h" | "-V" | "-shindex" | "-sptweaks")
}

fn parse_cli_flag(
    args: &[OsString],
    i: &mut usize,
    flag: &str,
) -> Result<Option<(String, String)>, ExitCode> {
    let rest = if let Some(r) = flag.strip_prefix("--") {
        r
    } else if matches!(flag, "-shindex" | "-sptweaks") {
        &flag[1..]
    } else {
        eprintln!("error: unknown argument `{flag}`");
        return Err(ExitCode::from(2));
    };
    if rest.is_empty() {
        eprintln!("error: unknown argument `{flag}`");
        return Err(ExitCode::from(2));
    }
    let (name, eq_val) = match rest.split_once('=') {
        Some((n, v)) => (n, Some(v)),
        None => (rest, None),
    };
    let key = name.replace('-', "_");
    if key == "smoke" || key == "help" || key == "version" || key == "conf" || key == "log_level" {
        eprintln!("error: unknown argument `{flag}`");
        return Err(ExitCode::from(2));
    }
    let val = if let Some(v) = eq_val {
        *i += 1;
        v.to_string()
    } else if is_bool_key(&key) {
        *i += 1;
        "1".to_string()
    } else {
        *i += 1;
        if *i >= args.len() {
            eprintln!("error: --{name} requires a value");
            return Err(ExitCode::from(2));
        }
        let next = args[*i].to_string_lossy().into_owned();
        if looks_like_flag(&next) {
            eprintln!("error: --{name} requires a value");
            return Err(ExitCode::from(2));
        }
        *i += 1;
        next
    };
    Ok(Some((key, val)))
}

fn cli_apply_err(e: crate::error::NodeError) -> ExitCode {
    let s = e.to_string();
    if s.contains("peertimeout must be a positive integer")
        || s.contains("minimumchainwork")
        || s.contains("must be hexadecimal")
        || s.contains("minimum chain")
        || s.contains("Invalid minimum work")
    {
        eprintln!("Error: {e}");
        ExitCode::from(1)
    } else {
        eprintln!("error: {e}");
        ExitCode::from(2)
    }
}

fn blocking_pool_size() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
        .max(4)
}

fn node_tokio_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(blocking_pool_size())
        .thread_name("tokio-rt-worker")
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OPERATOR_ENV_TEST_LOCK;
    use rbitcoin_primitives::Network;
    use std::time::{SystemTime, UNIX_EPOCH};

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

    #[test]
    fn help_and_version_exit_success() {
        assert_exit(cli_main(["rbitcoin-node", "--help"]), ExitCode::SUCCESS);
        assert_exit(cli_main(["rbitcoin-node", "-V"]), ExitCode::SUCCESS);
    }

    fn ready_config<I, T>(args: I) -> NodeConfig
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        match operator_config_from_args(args) {
            Ok(OperatorArgs::Ready { config, .. }) => config,
            other => panic!("expected assembled config, got {other:?}"),
        }
    }

    #[test]
    fn explicit_milestone_zero_sticks_on_mainnet() {
        use rbitcoin_consensus::{default_milestone_height, Milestone};

        let omitted = ready_config(["rbitcoin-node"]);
        assert_eq!(omitted.network, Network::Mainnet);
        assert_eq!(
            omitted.milestone_height,
            default_milestone_height(Network::Mainnet)
        );
        assert!(omitted.milestone().skips_scripts_at(1));

        let cli0 = ready_config(["rbitcoin-node", "--milestone", "0"]);
        assert_eq!(cli0.network, Network::Mainnet);
        assert_eq!(cli0.milestone_height, 0);
        assert_eq!(cli0.milestone(), Milestone::NONE);
        assert!(!cli0.milestone().skips_scripts_at(1));

        let alias0 = ready_config(["rbitcoin-node", "--assumevalid-height=0"]);
        assert_eq!(alias0.milestone_height, 0);
        assert_eq!(alias0.milestone(), Milestone::NONE);

        let dir = tmp_datadir();
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("m.conf");
        std::fs::write(&conf, "milestone=0\n").unwrap();
        let from_conf = ready_config(["rbitcoin-node", "--conf", conf.to_str().unwrap()]);
        assert_eq!(from_conf.network, Network::Mainnet);
        assert_eq!(from_conf.milestone_height, 0);
        assert_eq!(from_conf.milestone(), Milestone::NONE);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn flag_matrix_cli_equals_conf_apply_kv() {
        let _g = OPERATOR_ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut cfg = crate::config::NodeConfig::default();
        assert_eq!(
            cfg.apply_kv("network", "regtest").unwrap(),
            crate::config::ConfApply::Applied
        );
        assert_eq!(cfg.network, Network::Regtest);
        assert_eq!(
            cfg.apply_kv("chain", "signet").unwrap(),
            crate::config::ConfApply::Applied
        );
        assert_eq!(cfg.network, Network::Signet);

        let dir = tmp_datadir();
        assert_exit(
            cli_main([
                "rbitcoin-node",
                "--smoke",
                "--network=regtest",
                "--datadir",
                dir.to_str().unwrap(),
                "--noseeds=1",
                "--log-level",
                "error",
                "--milestone",
                "0",
            ]),
            ExitCode::SUCCESS,
        );
        let _ = std::fs::remove_dir_all(&dir);

        let dir = tmp_datadir();
        assert_exit(
            cli_main([
                "rbitcoin-node",
                "--smoke",
                "--chain=regtest",
                "--datadir",
                dir.to_str().unwrap(),
                "--no-seeds",
                "--log-level",
                "error",
                "--milestone",
                "0",
            ]),
            ExitCode::SUCCESS,
        );
        let _ = std::fs::remove_dir_all(&dir);

        let dir = tmp_datadir();
        let conf = dir.join("node.conf");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&conf, "network=testnet\n").unwrap();
        let smoke = dir.join("smoke");
        assert_exit(
            cli_main([
                "rbitcoin-node",
                "--smoke",
                "--conf",
                conf.to_str().unwrap(),
                "--network=regtest",
                "--datadir",
                smoke.to_str().unwrap(),
                "--no-seeds",
                "--log-level",
                "error",
                "--milestone",
                "0",
            ]),
            ExitCode::SUCCESS,
        );
        assert!(
            smoke.join("store").exists(),
            "CLI datadir must win over conf"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn testactivationheight_cli_smoke_regtest() {
        let _g = OPERATOR_ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmp_datadir();
        let code = cli_main([
            "rbitcoin-node",
            "--smoke",
            "--network",
            "regtest",
            "--datadir",
            dir.to_str().unwrap(),
            "--testactivationheight=csv@102",
            "--testactivationheight=dersig@50",
            "--whitelist=noban@127.0.0.1",
            "--permitbaremultisig=0",
            "--limitclustercount=10",
            "--minimumchainwork=0x65",
            "--no-seeds",
            "--log-level",
            "error",
            "--milestone",
            "0",
        ]);
        assert_exit(code, ExitCode::SUCCESS);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peertimeout_zero_is_init_error() {
        let dir = tmp_datadir();
        let code = cli_main([
            "rbitcoin-node",
            "--smoke",
            "--network",
            "regtest",
            "--datadir",
            dir.to_str().unwrap(),
            "--peertimeout=0",
            "--log-level",
            "error",
        ]);
        assert_exit(code, ExitCode::from(1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn minimumchainwork_rejects_non_hex() {
        let dir = tmp_datadir();
        let code = cli_main([
            "rbitcoin-node",
            "--smoke",
            "--network",
            "regtest",
            "--datadir",
            dir.to_str().unwrap(),
            "--minimumchainwork=test",
            "--log-level",
            "error",
        ]);
        assert_exit(code, ExitCode::from(1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_and_missing_value_errors() {
        assert_exit(cli_main(["rbitcoin-node", "--nope"]), ExitCode::from(2));
        assert_exit(cli_main(["rbitcoin-node", "--network"]), ExitCode::from(2));
        assert_exit(
            cli_main(["rbitcoin-node", "--network", "bogus"]),
            ExitCode::from(2),
        );
        assert_exit(cli_main(["rbitcoin-node", "--datadir"]), ExitCode::from(2));
        assert_exit(
            cli_main(["rbitcoin-node", "--datadir-cold"]),
            ExitCode::from(2),
        );
        assert_exit(
            cli_main(["rbitcoin-node", "--listen", "not-an-addr"]),
            ExitCode::from(2),
        );
        assert_exit(
            cli_main(["rbitcoin-node", "--log-level", "wat"]),
            ExitCode::from(2),
        );
        assert_exit(cli_main(["rbitcoin-node", "--api-log"]), ExitCode::from(2));
        assert_exit(cli_main(["rbitcoin-node", "--asmap"]), ExitCode::from(2));
        assert_exit(
            cli_main(["rbitcoin-node", "--max-outbound", "0"]),
            ExitCode::from(2),
        );
        assert_exit(
            cli_main(["rbitcoin-node", "--mempool-size-mb", "0"]),
            ExitCode::from(2),
        );
        // Missing values / parse rejects for advanced knobs.
        assert_exit(cli_main(["rbitcoin-node", "--conf"]), ExitCode::from(2));
        assert_exit(
            cli_main(["rbitcoin-node", "--maxinbound"]),
            ExitCode::from(2),
        );
        assert_exit(
            cli_main(["rbitcoin-node", "--maxinbound", "0"]),
            ExitCode::from(2),
        );
        assert_exit(
            cli_main(["rbitcoin-node", "--maxinbound", "nope"]),
            ExitCode::from(2),
        );
        assert_exit(
            cli_main(["rbitcoin-node", "--sptweaks-dust"]),
            ExitCode::from(2),
        );
        assert_exit(
            cli_main(["rbitcoin-node", "--sptweaks-dust", "nope"]),
            ExitCode::from(2),
        );
        // Bad conf path / invalid conf log_level.
        let dir = tmp_datadir();
        std::fs::create_dir_all(&dir).unwrap();
        assert_exit(
            cli_main([
                "rbitcoin-node",
                "--conf",
                dir.join("missing.conf").to_str().unwrap(),
                "--datadir",
                dir.join("d").to_str().unwrap(),
            ]),
            ExitCode::from(2),
        );
        let conf = dir.join("badlog.conf");
        std::fs::write(&conf, "log_level=notalevel\nnetwork=regtest\n").unwrap();
        assert_exit(
            cli_main([
                "rbitcoin-node",
                "--smoke",
                "--conf",
                conf.to_str().unwrap(),
                "--datadir",
                dir.join("d2").to_str().unwrap(),
                "--no-seeds",
            ]),
            ExitCode::from(2),
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn smoke_open_and_shutdown() {
        let _g = OPERATOR_ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmp_datadir();
        let code = cli_main([
            "rbitcoin-node",
            "--smoke",
            "--network",
            "regtest",
            "--datadir",
            dir.to_str().unwrap(),
            "--no-seeds",
            "--log-level",
            "error",
            "--milestone",
            "0",
            "--max-outbound",
            "2",
            "--maxinbound",
            "10",
            "--mempool-size-mb",
            "10",
        ]);
        assert_exit(code, ExitCode::SUCCESS);
        assert!(dir.join("store").is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn smoke_datadir_cold_puts_inwit_on_cold_store() {
        let _g = OPERATOR_ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmp_datadir();
        let hot = dir.join("hot");
        let cold = dir.join("cold");
        let code = cli_main([
            "rbitcoin-node",
            "--smoke",
            "--network",
            "regtest",
            "--datadir",
            hot.to_str().unwrap(),
            "--datadir-cold",
            cold.to_str().unwrap(),
            "--no-seeds",
            "--log-level",
            "error",
            "--milestone",
            "0",
        ]);
        assert_exit(code, ExitCode::SUCCESS);
        assert!(hot.join("store").is_dir());
        assert!(hot.join("store/txout.body").is_file());
        assert!(!hot.join("store/inwit.body").exists());
        assert!(cold.join("store/inwit.body").is_file());
        assert!(cold.join("store/inwit.idx").is_dir());
        assert!(hot.join("store").join("inwit.reloc").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn custom_signet_cli_smoke() {
        let dir = tmp_datadir();
        let code = cli_main([
            "rbitcoin-node",
            "--smoke",
            "--network",
            "signet",
            "--datadir",
            dir.to_str().unwrap(),
            "--signetchallenge",
            "51",
            "--signetblocktime",
            "60",
            "--no-seeds",
            "--log-level",
            "error",
            "--milestone",
            "0",
        ]);
        assert_exit(code, ExitCode::SUCCESS);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn help_lists_coreish_flags_not_only_env() {
        let _g = OPERATOR_ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Parse accepts Core-like aliases (not env-only).
        let dir = tmp_datadir();
        let code = cli_main([
            "rbitcoin-node",
            "--smoke",
            "--chain",
            "regtest",
            "--datadir",
            dir.to_str().unwrap(),
            "--assumevalid-height",
            "0",
            "--maxconnections",
            "5",
            "--maxmempool",
            "8",
            "--log-level",
            "error",
            "--noseeds",
        ]);
        assert_exit(code, ExitCode::SUCCESS);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn conf_file_then_cli_override() {
        let _g = OPERATOR_ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmp_datadir();
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("node.conf");
        std::fs::write(&conf, "network=signet\nmaxinbound=33\n").unwrap();
        let data = dir.join("data");
        let code = cli_main([
            "rbitcoin-node",
            "--smoke",
            "--conf",
            conf.to_str().unwrap(),
            "--datadir",
            data.to_str().unwrap(),
            "--network",
            "regtest", // CLI overrides conf network
            "--log-level",
            "error",
            "--no-seeds",
            "--milestone",
            "0",
        ]);
        assert_exit(code, ExitCode::SUCCESS);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CLI omit of inbound must not clobber pre-set advanced envs.
    #[test]
    fn cli_omit_preserves_advanced_env() {
        let _g = OPERATOR_ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("RBITCOIN_P2P_MAX_INBOUND", "91");
        let dir = tmp_datadir();
        let code = cli_main([
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
            // no --maxinbound
        ]);
        assert_exit(code, ExitCode::SUCCESS);
        assert_eq!(
            std::env::var("RBITCOIN_P2P_MAX_INBOUND").as_deref(),
            Ok("91")
        );
        std::env::remove_var("RBITCOIN_P2P_MAX_INBOUND");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn conf_log_level_applied_when_cli_omits() {
        let _g = OPERATOR_ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmp_datadir();
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("log.conf");
        std::fs::write(&conf, "log_level=warn\nnetwork=regtest\n").unwrap();
        let data = dir.join("data");
        // No --log-level: conf warn must init without error.
        let code = cli_main([
            "rbitcoin-node",
            "--smoke",
            "--conf",
            conf.to_str().unwrap(),
            "--datadir",
            data.to_str().unwrap(),
            "--no-seeds",
            "--milestone",
            "0",
        ]);
        assert_exit(code, ExitCode::SUCCESS);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
