use crate::config::{ConfApply, NodeConfig};
use crate::inhibit::SuspendInhibit;
use crate::run::{run_node, run_p2p};
use rbitcoin_consensus::{default_milestone_height, mainnet_min_chain_work_be};
use rbitcoin_log::{self, error, info, warn, Level};
use rbitcoin_store::HeadScale;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

#[allow(clippy::large_enum_variant)] // uring vs pool vs iocp backends
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
    match parse_operator_flags(&args)? {
        OperatorFlagEnd::Help => Ok(OperatorArgs::Help),
        OperatorFlagEnd::Version => Ok(OperatorArgs::Version),
        OperatorFlagEnd::Flags(parsed) => {
            let mut config = NodeConfig::default();
            if let Some(ref cp) = parsed.conf_path {
                if let Err(e) = config.merge_conf_file(cp) {
                    eprintln!("error: {e}");
                    return Err(ExitCode::from(2));
                }
                config.conf_path = Some(cp.clone());
            }
            apply_operator_kvs(&mut config, parsed.kvs)?;
            finish_operator_config(config, parsed.smoke, parsed.log_level_cli)
        }
    }
}

enum OperatorFlagEnd {
    Help,
    Version,
    Flags(ParsedOperatorFlags),
}

struct ParsedOperatorFlags {
    smoke: bool,
    conf_path: Option<PathBuf>,
    log_level_cli: Option<Option<Level>>,
    kvs: Vec<(String, String)>,
}

fn parse_operator_flags(args: &[OsString]) -> Result<OperatorFlagEnd, ExitCode> {
    let mut i = 1usize;
    let mut smoke = false;
    let mut conf_path: Option<PathBuf> = None;
    let mut log_level_cli: Option<Option<Level>> = None;
    let mut kvs: Vec<(String, String)> = Vec::new();

    while i < args.len() {
        let a = args[i].to_string_lossy();
        match a.as_ref() {
            "--help" | "-h" => {
                eprintln!("{}", operator_usage());
                return Ok(OperatorFlagEnd::Help);
            }
            "--version" | "-V" => {
                eprintln!("rbitcoin-node {}", env!("CARGO_PKG_VERSION"));
                return Ok(OperatorFlagEnd::Version);
            }
            "--smoke" => {
                smoke = true;
                i += 1;
            }
            "--conf" => match take_arg(args, &mut i, "--conf") {
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
            "--log-level" => match take_arg(args, &mut i, "--log-level") {
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
            other => match parse_cli_flag(args, &mut i, other) {
                Ok(Some(kv)) => kvs.push(kv),
                Ok(None) => {}
                Err(c) => return Err(c),
            },
        }
    }
    Ok(OperatorFlagEnd::Flags(ParsedOperatorFlags {
        smoke,
        conf_path,
        log_level_cli,
        kvs,
    }))
}

fn apply_operator_kvs(config: &mut NodeConfig, kvs: Vec<(String, String)>) -> Result<(), ExitCode> {
    let mut saw_listen = false;
    let mut saw_connect = false;
    let mut saw_seednode = false;
    for (key, val) in kvs {
        if key == "listen" && !saw_listen {
            config.listen.p2p = crate::config::P2pListen::Auto;
            config.listen.p2p_extra.clear();
            saw_listen = true;
        }
        if key == "no_listen" && !saw_listen {
            config.listen.p2p = crate::config::P2pListen::Auto;
            config.listen.p2p_extra.clear();
            saw_listen = true;
        }
        if key == "connect" && !saw_connect {
            config.listen.connect.clear();
            config.listen.connect_dns.clear();
            saw_connect = true;
        }
        if key == "seed_node" && !saw_seednode {
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
    Ok(())
}

fn finish_operator_config(
    mut config: NodeConfig,
    smoke: bool,
    log_level_cli: Option<Option<Level>>,
) -> Result<OperatorArgs, ExitCode> {
    if let Err(e) = config.subversion() {
        eprintln!("{e}");
        return Err(ExitCode::from(1));
    }

    if !config.milestone_explicit {
        config.milestone_height = default_milestone_height(config.network);
    }
    if config.minimum_chain_work.is_none()
        && config.network == rbitcoin_primitives::Network::Mainnet
    {
        config.minimum_chain_work = Some(mainnet_min_chain_work_be());
    }
    config.smoke = smoke;
    config.absorb_inbound_env();
    config.resolve_listen_defaults();
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
                print_run_err(&e);
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
                print_run_err(&e);
                ExitCode::FAILURE
            }
        };
        rt.shutdown_timeout(std::time::Duration::from_secs(2));
        code
    }
}

fn operator_usage() -> String {
    format!(
        "rbitcoin-node {} — usage:\n\
  rbitcoin-node [--conf FILE] [--datadir PATH] [--datadir-cold PATH] [--network NET] \\\n\
    [--signet-challenge HEX] [--signet-block-time SECS] \\\n\
    [--listen ADDR] [--no-listen] [--connect ADDR]... [--seed-node HOST]... [--proxy HOST:PORT] [--onion HOST:PORT] [--proxy-randomize[=0|1]] [--only-net NET]... \\\n\
    [--tor-control [HOST:PORT]] [--tor-control-cookie PATH] [--tor-control-password PASS] \\\n\
    [--i2p-sam [HOST:PORT]] [--i2p-accept-incoming] \\\n\
    [--electrum-listen ADDR] [--esplora-listen ADDR] [--esplora-onion[=0|1]] [--health-listen [ADDR]] [--metrics] \\\n\
    [--sh-index] [--block-filter-index] [--prune-seqsigwit] [--prune-seqsigwit-ram-threshold-bytes N] [--sp-tweaks] [--sp-tweaks-dust SATS] [--max-sh-creates N] [--electrum-max-subs N] [--esplora-block-template] \\\n\
    [--rpc] [--rpc-listen [ADDR]] [--rpc-socket PATH] [--rpc-token-file PATH] [--rpc-cookie-file PATH] [--rpc-work-queue N] \\\n\
    [--milestone HEIGHT] \\\n\
    [--max-outbound N] [--max-inbound N] \\\n\
    [--mempool-size-mb N] [--mempool-expiry HOURS] \\\n\
    [--test-activation-height name@HEIGHT] [--persist-mempool[=0|1]] [--trusted] [--always-relay] [--relay] \\\n\
    [--net-permission SPEC] [--net-permission-bind SPEC] [--net-permission-relay[=0|1]] [--net-permission-force-relay[=0|1]] \\\n\
    [--blocks-only] [--prefill-compact[=0|1]] [--min-relay-tx-fee BTC] \\\n\
    [--limit-cluster-count N] [--limit-cluster-size KVB] [--peer-timeout SECS] \\\n\
    [--external-ip IP] [--ua-comment STR] \\\n\
    [--min-chain-work HEX] [--max-tip-age SECS] [--check-blocks N] [--mock-time UNIX] \\\n\
    [--block-version N] [--block-min-tx-fee BTC] [--bytes-per-sigop N] [--block-reserved-sigops N] [--alert-notify CMD] [--startup-notify CMD] \\\n\
    [--max-run-secs N] [--log-level LEVEL] [--api-log PATH] [--asmap PATH] \\\n\
    [--no-seeds] [--no-listen] [--no-discover] [--listen-onion] [--cjdns-reachable] [--smoke] [--inhibit-suspend]\n\n\
Networks: mainnet|testnet|signet|regtest.\n\
Custom Signet: --signet-challenge HEX [--signet-block-time SECS].\n\
Log level: error|warn|info|debug|trace|off (CLI > conf log_level > RBITCOIN_LOG / RUST_LOG).\n\
API log: --api-log PATH writes one JSON line per Electrum/Esplora/RPC call (also TRACE `api:`).\n\
Asmap: --asmap PATH loads a Core ip_asn.dat (relative to datadir). Unset tries {{datadir}}/ip_asn.dat.\n\
Milestone: skip script/sig checks at/below HEIGHT.\n\
  Defaults: mainnet 840000 anchored to block 0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5\n\
  (skip only on that header path, and only when header work meets min chain work),\n\
  signet 0, testnet 2500000, regtest 0. Explicit HEIGHT is height-only. Use 0 for full scripts.\n\
Check-blocks: --check-blocks N revalidates the last N confirmed heights on open (default 6; 0 = all).\n\
Mempool: --mempool-size-mb (default ~300 MiB weight budget).\n\
Peers: --max-outbound (default 16 live download), --max-inbound (default 125).\n\
  --proxy HOST:PORT SOCKS5 for all P2P outbound; --onion HOST:PORT SOCKS for onion (02).\n\
  --proxy-randomize (default on) uses a fresh SOCKS username per peer (Tor circuit isolation).\n\
  --tor-control [HOST:PORT] talks to system tor (default 127.0.0.1:9051). Cookie or password AUTH;\n\
  failed AUTH is a start error. Unset: no control connection.\n\
  --tor-control-cookie PATH (default /run/tor/control.authcookie). --tor-control-password PASS.\n\
  --i2p-sam [HOST:PORT] SAM v3 to system i2pd (default 127.0.0.1:7656). --only-net=i2p requires it.\n\
  --i2p-accept-incoming persist {{datadir}}/i2p/p2p.priv and STREAM FORWARD to the P2P bind. Needs --listen.\n\
  --listen-onion ADD_ONION the P2P port (loopback bind even with --no-listen). Needs --tor-control and --max-inbound > 0.\n\
  --cjdns-reachable treat fc00::/8 as CJDNS (dial and advertise). --only-net=cjdns requires it.\n\
  --trusted / --always-relay / --relay are inbound permission knobs.\n\
  --net-permission / --net-permission-bind are CIDR or bind grants (noban, relay, …; IPv4 and IPv6).\n\
  --net-permission-relay (default on) / --net-permission-force-relay (default off) are implicit bits on a bare CIDR grant.\n\
Scripthash: --sh-index (default off) builds Class B for Electrum/Esplora address history.\n\
Block filters: --block-filter-index (default off) builds BIP158 basic filters. Independent of --sh-index.\n\
  Electrum/Esplora start without it; scripthash/address methods fail closed.\n\
  --prune-seqsigwit refuse seqsigwit reconstruct below tip-288 heights; advertise NETWORK_LIMITED.\n\
    Kept heights are store/seqsigwit.window/{{height}}.bin plus a RAM cache. Unpruned nodes read seqsigwit.body.\n\
  --prune-seqsigwit-ram-threshold-bytes N RAM cap for that cache (default 268435456; 0 keeps nothing in RAM).\n\
  --max-sh-creates N refuses an unpaged Electrum/Esplora join with more than N creates (default 10000; 0 = unlimited). A paged history request is still served.\n\
  --electrum-max-subs N caps blockchain.scripthash.subscribe per Electrum connection (default 10000; >= 1). Wallets subscribe every address up to their gap limit.\n\
  --esplora-block-template enables GET /block-template (GBT template JSON; default off).\n\
  --esplora-onion (default on) ADD_ONION for --esplora-listen when --tor-control is set.\n\
Silent payments: --sp-tweaks (default off) writes/serves the thin BIP-352 tweak index.\n\
  Not with --prune-seqsigwit (tweaks read scriptSig and witness).\n\
  --sp-tweaks-dust SATS omits served P2TR outs with value <= SATS (default 1000; 0 = all; 546 = Cake electrs).\n\
Health: --health-listen [ADDR] serves GET /healthz, GET /readyz, and GET /progress (JSON:\n\
  the running index build, rebuild, or backfill stage, at any log level) from the first\n\
  second of startup (default 127.0.0.1:9332). Unauthenticated; keep it on loopback or a\n\
  probe-only network. --metrics adds Prometheus GET /metrics there (needs --health-listen).\n\
RPC: --rpc unix socket {{datadir}}/rpc.sock; --rpc-listen [ADDR] adds TCP (default 127.0.0.1 and Core-matching port). Token {{datadir}}/rpc.token (Bearer); --rpc-cookie-file opts TCP into Core cookie HTTP Basic. No --rpcuser.\n\
Cold files: --datadir-cold PATH puts Class A seqsigwit.body/idx under PATH/store (HDD).\n\
  Default (flag omitted): hot and cold files both live under --datadir.\n\
Conf: --conf FILE (snake_case key=value; CLI kebab overrides conf). See OPERATOR.md and docs/rpc.md.\n\
Advanced debug/IO knobs remain RBITCOIN_* env (not required for normal sync; preserved if CLI omits).\n\
IBD densify: up to 1024 concurrent getdata, max 16 in transit per peer.\n\
  Relay / RPC initialblockdownload after catch-up: --min-chain-work + --max-tip-age (24h).",
        env!("CARGO_PKG_VERSION")
    )
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
        "sh_index"
            | "block_filter_index"
            | "prune_seqsigwit"
            | "sp_tweaks"
            | "esplora_block_template"
            | "esplora_onion"
            | "blocks_only"
            | "prefill_compact"
            | "persist_mempool"
            | "net_permission_relay"
            | "net_permission_force_relay"
            | "no_seeds"
            | "no_listen"
            | "no_discover"
            | "listen_onion"
            | "cjdns_reachable"
            | "proxy_randomize"
            | "i2p_accept_incoming"
            | "inhibit_suspend"
            | "metrics"
            | "trusted"
            | "always_relay"
            | "relay"
            | "rpc"
    )
}

fn is_optional_addr_key(key: &str) -> bool {
    matches!(
        key,
        "rpc_listen"
            | "electrum_listen"
            | "esplora_listen"
            | "health_listen"
            | "tor_control"
            | "i2p_sam"
    )
}

fn looks_like_flag(s: &str) -> bool {
    s.starts_with("--") || matches!(s, "-h" | "-V")
}

fn parse_cli_flag(
    args: &[OsString],
    i: &mut usize,
    flag: &str,
) -> Result<Option<(String, String)>, ExitCode> {
    let rest = if let Some(r) = flag.strip_prefix("--") {
        r
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
    } else if is_optional_addr_key(&key) {
        *i += 1;
        if *i >= args.len() {
            String::new()
        } else {
            let next = args[*i].to_string_lossy().into_owned();
            if looks_like_flag(&next) {
                String::new()
            } else {
                *i += 1;
                next
            }
        }
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

fn print_run_err(e: &crate::error::NodeError) {
    match e {
        crate::error::NodeError::FutureTip | crate::error::NodeError::Init(_) => eprintln!("{e}"),
        crate::error::NodeError::Locked(_) => eprintln!("Error: {e}"),
        _ => error!("{e}"),
    }
}

fn cli_apply_err(e: crate::error::NodeError) -> ExitCode {
    match e {
        crate::error::NodeError::Init(_) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
        other => {
            eprintln!("error: {other}");
            ExitCode::from(2)
        }
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

    /// What argv and the conf file assemble before `run_node`. The smoke
    /// journey (`node_cli_and_surface_smoke`) sees only the exit code and
    /// the datadir; these values and the help text are not reported by any
    /// running surface, so this is the one place they are read.
    #[allow(clippy::cognitive_complexity)] // one operator's conf and argv
    #[test]
    fn operator_conf_and_argv() {
        use crate::config::P2pListen;
        use rbitcoin_consensus::Milestone;
        let _g = OPERATOR_ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

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
            "--prune-seqsigwit-ram-threshold-bytes",
            "--sp-tweaks",
            "--sp-tweaks-dust",
            "--esplora-block-template",
            "--esplora-onion",
            "--rpc",
            "--rpc-listen",
            "--rpc-socket",
            "--rpc-token-file",
            "--rpc-cookie-file",
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
            operator_config_from_args(["rbitcoin-node", "-V"]),
            Ok(OperatorArgs::Version)
        ));
        assert!(matches!(
            operator_config_from_args(["rbitcoin-node", "--log-level=off"]),
            Ok(OperatorArgs::Ready {
                log_level_cli: Some(None),
                ..
            })
        ));

        // No argv: mainnet with the anchored milestone and the chainwork floor.
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

        // A custom signet operator's conf file.
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
        match operator_config_from_args(["rbitcoin-node", "--conf", bad_dust.to_str().unwrap()]) {
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
        let signet_skip = ready_config([
            "rbitcoin-node",
            "--network=signet",
            "--milestone",
            "2000000",
        ]);
        assert!(signet_skip.milestone().skips_scripts_at(1));
        let work = ready_config(["rbitcoin-node", "--min-chain-work=0x65"]);
        assert_eq!(work.minimum_chain_work.unwrap()[31], 0x65);

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
            cli_main(["rbitcoin-node", "--bytes-per-sigop=x"]),
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
    }

    include!("overlay_config_journey.rs");

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

    /// RPC binds only after catch-up, so a bad `--rpc-cookie-file` must fail
    /// the launch rather than surface as a warning after IBD.
    #[test]
    fn cli_rejects_bad_rpc_cookie_at_launch() {
        let _g = OPERATOR_ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
            cli_main(args)
        };
        assert_exit(run(&["--rpc-listen"]), ExitCode::FAILURE);
        std::fs::write(&cookie, "__cookie__:secret\n").unwrap();
        assert_exit(run(&["--rpc-listen"]), ExitCode::FAILURE);
        std::fs::write(&cookie, "__cookie__:secret").unwrap();
        // Socket-only RPC would silently ignore the cookie (message pinned in config.rs).
        assert_exit(run(&["--rpc"]), ExitCode::FAILURE);
        assert_exit(run(&["--rpc-listen"]), ExitCode::SUCCESS);
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
            // no --max-inbound
        ]);
        assert_exit(code, ExitCode::SUCCESS);
        assert_eq!(
            std::env::var("RBITCOIN_P2P_MAX_INBOUND").as_deref(),
            Ok("91")
        );
        std::env::remove_var("RBITCOIN_P2P_MAX_INBOUND");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
