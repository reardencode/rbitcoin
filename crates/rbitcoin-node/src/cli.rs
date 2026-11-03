use crate::config::{ConfApply, NodeConfig, NodeEnv};
use crate::inhibit::SuspendInhibit;
use crate::run::{run_node, run_p2p};
use rbitcoin_consensus::{default_milestone_height, default_min_chain_work_be};
use rbitcoin_log::{self, error, info, warn, Level};
use rbitcoin_store::HeadScale;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

#[allow(clippy::large_enum_variant)] // uring vs pool vs iocp backends
/// CLI parse result before log init / datadir open / run.
#[derive(Debug)]
pub enum OperatorArgs {
    Help,
    Version,
    Ready {
        config: NodeConfig,
        log_level_cli: Option<Option<Level>>,
    },
}

/// Assemble [`NodeConfig`] from argv (conf then CLI `apply_kv`), then `env`. Does not open the store.
pub fn operator_config_from_args<I, T>(args: I, env: &NodeEnv) -> Result<OperatorArgs, ExitCode>
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
            config.hot_digest = parsed.hot_digest;
            config.assumehot = parse_assumehot(parsed.assumehot_from, parsed.assumehot)?;
            finish_operator_config(config, parsed.smoke, parsed.log_level_cli, env)
        }
    }
}

#[doc(hidden)]
pub enum OperatorFlagEnd {
    Help,
    Version,
    Flags(ParsedOperatorFlags),
}

#[doc(hidden)]
pub struct ParsedOperatorFlags {
    pub smoke: bool,
    pub hot_digest: bool,
    pub assumehot_from: Option<PathBuf>,
    pub assumehot: Option<String>,
    pub conf_path: Option<PathBuf>,
    pub log_level_cli: Option<Option<Level>>,
    pub kvs: Vec<(String, String)>,
}

#[doc(hidden)]
pub fn parse_operator_flags(args: &[OsString]) -> Result<OperatorFlagEnd, ExitCode> {
    let mut i = 1usize;
    let mut smoke = false;
    let mut hot_digest = false;
    let mut assumehot_from: Option<PathBuf> = None;
    let mut assumehot: Option<String> = None;
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
            "--hot-digest" => {
                hot_digest = true;
                i += 1;
            }
            "--assumehot-from" => match take_arg(args, &mut i, "--assumehot-from") {
                Ok(v) => assumehot_from = Some(PathBuf::from(v)),
                Err(c) => return Err(c),
            },
            "--assumehot" => match take_arg(args, &mut i, "--assumehot") {
                Ok(v) => assumehot = Some(v),
                Err(c) => return Err(c),
            },
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
        hot_digest,
        assumehot_from,
        assumehot,
        conf_path,
        log_level_cli,
        kvs,
    }))
}

#[doc(hidden)]
pub fn apply_operator_kvs(
    config: &mut NodeConfig,
    kvs: Vec<(String, String)>,
) -> Result<(), ExitCode> {
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
        if key == "tor_control_password" {
            use std::sync::atomic::{AtomicBool, Ordering};
            static WARNED: AtomicBool = AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::Relaxed) {
                rbitcoin_log::warn!(
                    "node: --tor-control-password puts the password on the command line"
                );
            }
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

#[doc(hidden)]
pub fn finish_operator_config(
    mut config: NodeConfig,
    smoke: bool,
    log_level_cli: Option<Option<Level>>,
    env: &NodeEnv,
) -> Result<OperatorArgs, ExitCode> {
    if let Err(e) = config.subversion() {
        eprintln!("{e}");
        return Err(ExitCode::from(1));
    }

    if !config.milestone_explicit {
        config.milestone_height = default_milestone_height(config.network);
    }
    if config.minimum_chain_work.is_none() {
        config.minimum_chain_work = default_min_chain_work_be(config.network);
    }
    config.smoke = smoke;
    config.absorb_inbound_env(env);
    if let Some(stop) = env.bq_assign_stop_bytes {
        config.bq_assign_stop_bytes = stop;
    }
    config.sh_force_rebuild |= env.sh_force_rebuild;
    config.rpc.package_dialect |= env.rpc_package_dialect;
    config.rpc.wait_tip_idle |= env.rpc_wait_tip_idle;
    config.resolve_listen_defaults();
    if let Err(e) = config.seal_trust_peer() {
        eprintln!("error: {e}");
        return Err(ExitCode::from(2));
    }
    Ok(OperatorArgs::Ready {
        config,
        log_level_cli,
    })
}

/// The process shell: argv and env from the OS, then [`cli_main`]. A malformed
/// `RBITCOIN_*` value exits 2 before anything starts.
pub fn process_main() -> ExitCode {
    match NodeEnv::from_env() {
        Ok(env) => cli_main(std::env::args_os(), env),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

/// Process entry used by [`process_main`] and high-level scenarios.
pub fn cli_main<I, T>(args: I, env: NodeEnv) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let (mut config, log_level_cli) = match operator_config_from_args(args, &env) {
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

    if config.hot_digest {
        return hot_digest_main(config);
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
                if env.test_drop_store {
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

/// `--assumehot-from` / `--assumehot`: both or neither, and the hash is the
/// 64-hex digest field that `--hot-digest` prints. CLI only: a conf line
/// would import again on every start.
fn parse_assumehot(
    from: Option<PathBuf>,
    hash: Option<String>,
) -> Result<Option<(PathBuf, [u8; 32])>, ExitCode> {
    match (from, hash) {
        (None, None) => Ok(None),
        (Some(_), None) => {
            eprintln!("error: --assumehot-from requires --assumehot HASH");
            Err(ExitCode::from(2))
        }
        (None, Some(_)) => {
            eprintln!("error: --assumehot requires --assumehot-from DATADIR");
            Err(ExitCode::from(2))
        }
        (Some(from), Some(hash)) => {
            match rbitcoin_primitives::hex::decode(&hash).map(<[u8; 32]>::try_from) {
                Ok(Ok(digest)) => Ok(Some((from, digest))),
                _ => {
                    eprintln!(
                        "error: --assumehot must be 64 hex digits (the digest --hot-digest prints)"
                    );
                    Err(ExitCode::from(2))
                }
            }
        }
    }
}

/// `--hot-digest`: open the store, print [`hot_digest_line`], exit. An empty
/// store has no digest and exits 1.
fn hot_digest_main(config: NodeConfig) -> ExitCode {
    let network = config.network;
    let handle = match run_node(config) {
        Ok(handle) => handle,
        Err(e) => {
            print_run_err(&e);
            return ExitCode::FAILURE;
        }
    };
    let code = match handle.query.hot_digest() {
        Ok(Some(d)) => {
            println!("{}", hot_digest_line(network, &d));
            ExitCode::SUCCESS
        }
        Ok(None) => {
            eprintln!("hot-digest: store is empty");
            ExitCode::FAILURE
        }
        Err(e) => {
            error!("hot-digest: {e}");
            ExitCode::FAILURE
        }
    };
    if let Err(e) = handle.shutdown() {
        error!("shutdown error: {e}");
        return ExitCode::FAILURE;
    }
    code
}

/// `network height blockhash digest`: the tip hash in display (reversed)
/// order, the digest as plain lower hex.
pub fn hot_digest_line(
    network: rbitcoin_primitives::Network,
    d: &rbitcoin_query::hot_digest::HotDigest,
) -> String {
    use rbitcoin_primitives::hex;
    format!(
        "{} {} {} {}",
        network.as_str(),
        d.height,
        hex::display_hash_hex(d.tip_hash),
        hex::encode(d.digest),
    )
}

#[doc(hidden)]
pub fn operator_usage() -> String {
    format!(
        "rbitcoin-node {} — usage:\n\
  rbitcoin-node [--conf FILE] [--datadir PATH] [--datadir-cold PATH] [--network NET] \\\n\
    [--signet-challenge HEX] [--signet-block-time SECS] \\\n\
    [--listen ADDR] [--no-listen] [--connect ADDR]... [--trust-peer ADDR] [--seed-node HOST]... [--proxy HOST:PORT] [--onion HOST:PORT] [--proxy-randomize[=0|1]] [--only-net NET]... \\\n\
    [--tor-control [HOST:PORT]] [--tor-control-cookie PATH] [--tor-control-password PASS] \\\n\
    [--i2p-sam [HOST:PORT]] [--i2p-accept-incoming] \\\n\
    [--electrum-listen ADDR] [--esplora-listen ADDR] [--esplora-onion[=0|1]] [--health-listen [ADDR]] [--metrics] \\\n\
    [--sv2-tp-listen ADDR] [--sv2-tp-authority-sec KEY] [--sv2-tp-authority-sec-file PATH] [--sv2-tp-cert-validity SECS] [--sv2-tp-stale-grace SECS] [--sv2-tp-idle-timeout SECS] [--sv2-tp-fee-delta SATS] [--sv2-tp-template-interval SECS] \\\n\
    [--sh-index] [--block-filter-index] [--prune-seqsigwit] [--prune-seqsigwit-ram-threshold-bytes N] [--datadir-hdd] [--sp-tweaks] [--sp-tweaks-dust SATS] [--max-sh-creates N] [--heavy-sh-creates N] [--electrum-max-subs N] [--esplora-max-inflight N] [--esplora-block-template] \\\n\
    [--rpc] [--rpc-listen [ADDR]] [--rest] [--rpc-socket PATH] [--rpc-token-file PATH] [--rpc-cookie-file PATH] [--rpc-cookie-perms owner|group|all] [--rpc-work-queue N] \\\n\
    [--milestone HEIGHT] \\\n\
    [--max-outbound N] [--max-inbound N] \\\n\
    [--mempool-size-mb N] [--mempool-expiry HOURS] \\\n\
    [--test-activation-height name@HEIGHT] [--regtest-pow-bits BITS] [--persist-mempool[=0|1]] [--trusted] [--always-relay] [--relay] \\\n\
    [--net-permission SPEC] [--net-permission-bind SPEC] [--net-permission-relay[=0|1]] [--net-permission-force-relay[=0|1]] \\\n\
    [--blocks-only] [--prefill-compact[=0|1]] [--min-relay-tx-fee BTC] \\\n\
    [--limit-cluster-count N] [--limit-cluster-size KVB] [--peer-timeout SECS] \\\n\
    [--external-ip IP] [--ua-comment STR] \\\n\
    [--min-chain-work HEX] [--max-tip-age SECS] [--check-blocks N] [--mock-time UNIX] \\\n\
    [--block-version N] [--block-min-tx-fee BTC] [--bytes-per-sigop N] [--block-reserved-sigops N] [--alert-notify CMD] [--startup-notify CMD] \\\n\
    [--max-run-secs N] [--log-level LEVEL] [--api-log PATH] [--asmap PATH] \\\n\
    [--no-seeds] [--no-listen] [--no-discover] [--listen-onion] [--cjdns-reachable] [--smoke] [--hot-digest] [--assumehot-from DATADIR --assumehot HASH] [--inhibit-suspend]\n\n\
Networks: mainnet|testnet|signet|regtest.\n\
Custom Signet: --signet-challenge HEX [--signet-block-time SECS].\n\
Log level: error|warn|info|debug|trace|off (CLI > conf log_level > RBITCOIN_LOG / RUST_LOG).\n\
API log: --api-log PATH writes one JSON line per Electrum/Esplora/RPC call (also TRACE `api:`).\n\
Asmap: --asmap PATH loads a Core ip_asn.dat (relative to datadir). Unset tries {{datadir}}/ip_asn.dat.\n\
Milestone: skip script/sig checks at/below HEIGHT.\n\
  Defaults: mainnet 840000 anchored to block 0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5,\n\
  testnet 2500000 anchored to block 0000000000000093bcb68c03a9a168ae252572d348a2eaeba2cdf9231d73206f\n\
  (skip only on that header path, and only when header work meets that network's min chain work),\n\
  signet 0, regtest 0. Explicit HEIGHT is height-only. Use 0 for full scripts.\n\
Check-blocks: --check-blocks N revalidates the last N confirmed heights on open (default 6; 0 = all).\n\
Hot digest: --hot-digest prints `network height tiphash digest` for this store and exits.\n\
Assumehot: --assumehot-from DATADIR --assumehot HASH imports a cleanly stopped datadir's store into\n\
  this empty one, on the first start only. HASH is the digest --hot-digest printed there. Each header\n\
  and block body is checked and spends are recomputed; scripts are not run. CLI only (not conf).\n\
Mempool: --mempool-size-mb (default 300 → 300e6 WU; N × 1_000_000 weight, not MiB).\n\
Peers: --max-outbound (default 16 live download), --max-inbound (default 200; half for tx-relaying peers).\n\
Trust-peer: --trust-peer ADDR (conf trustpeer=) dials only that address, the same grammar as --connect.\n\
  It turns listening off and sets max-inbound to 0. A second address, a different --connect,\n\
  --seed-node, --listen, --listen-onion, or --max-inbound greater than 0 is a start error.\n\
  Consensus checks still run. A warn-and-apply fault from that peer is logged\n\
  trust-peer: and kept; other blocks and transactions stay strict (COMPAT.md).\n\
  Policy stays a hard error.\n\
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
  --heavy-sh-creates N runs unpaged Electrum/Esplora joins with more than N creates one at a time across the node (default 10000; 0 = no limit). Lighter joins stay parallel.\n\
  --electrum-max-subs N caps blockchain.scripthash.subscribe per Electrum connection (default 10000; >= 1). Wallets subscribe every address up to their gap limit.\n\
  --esplora-max-inflight N caps Esplora requests in flight across the whole listener (default 256; >= 1). Further requests wait for a slot; the wait counts against the request timeout (408).\n\
  --esplora-block-template enables GET /block-template (GBT template JSON; default off).\n\
  --esplora-onion (default on) ADD_ONION for --esplora-listen when --tor-control is set.\n\
Silent payments: --sp-tweaks (default off) writes/serves the thin BIP-352 tweak index.\n\
  Not with --prune-seqsigwit (tweaks read scriptSig and witness).\n\
  --sp-tweaks-dust SATS omits served P2TR outs with value <= SATS (default 1000; 0 = all; 546 = Cake electrs).\n\
Health: --health-listen [ADDR] serves GET /healthz, GET /readyz, and GET /progress (JSON:\n\
  the running index build, rebuild, or backfill stage, at any log level) from the first\n\
  second of startup (default 127.0.0.1:9332). Unauthenticated; keep it on loopback or a\n\
  probe-only network. --metrics adds Prometheus GET /metrics there (needs --health-listen).\n\
SV2: --sv2-tp-listen ADDR serves the Stratum v2 Template Distribution Protocol (Noise over TCP; default off).\n\
  Requires --sv2-tp-authority-sec KEY (secp256k1 secret, 64 hex or key-utils base58check; argv exposes it) or --sv2-tp-authority-sec-file PATH\n\
  (the same hex in a file). The x-only pubkey is logged.\n\
  --sv2-tp-cert-validity SECS per-connection certificate lifetime, at most 4294967295 (default 3600).\n\
  --sv2-tp-stale-grace SECS keeps a replaced tip's templates answering for SECS, at most 86400 (default 10).\n\
  --sv2-tp-idle-timeout SECS drops a client that sends no frame for SECS after its first CoinbaseOutputConstraints,\n\
    at most 86400 (default 0: never; SRI pools and JDCs stay silent between shares).\n\
  --sv2-tp-fee-delta SATS pushes a same-tip template once its fees gain SATS over the last one sent (default 1000).\n\
  --sv2-tp-template-interval SECS checks for that gain every SECS, 1 to 86400 (default 5).\n\
RPC: --rpc unix socket {{datadir}}/rpc.sock; --rpc-listen [ADDR] adds TCP (default 127.0.0.1 and Core-matching port). Token {{datadir}}/rpc.token (Bearer), created mode 0600; an existing token must be owner-only on Unix. Delete a wider file and start again so the node mints a new token (Windows has no mode bits). --rpc-cookie-file opts TCP into Core cookie HTTP Basic. --rpc-cookie-perms owner|group|all (default owner) is the widest Unix mode that file may have (owner 0600, group 0640, all 0644); the node never creates or chmods it. Windows has no mode bits. No --rpcuser. --rest turns on unauthenticated /rest/ on those listeners (off unless set).\n\
Cold files: --datadir-cold PATH puts append-only IBD files under PATH/store\n\
  (seqsigwit, txstat, input, and blockfilter / sp_tweaks once enabled).\n\
  Default (flag omitted): those files live under --datadir. --prune-seqsigwit\n\
  is separate: it drops old seqsigwit and keeps a 288-height window on the hot store.\n\
  --datadir-hdd says the main datadir is rotating media. The node does not probe the device.\n\
  Default off keeps the SSD confirm schedule.\n\
Conf: --conf FILE (snake_case key=value; CLI kebab overrides conf). See OPERATOR.md and docs/rpc.md.\n\
Advanced debug/IO knobs remain RBITCOIN_* env (not required for normal sync; preserved if CLI omits).\n\
IBD densify: up to 1024 concurrent getdata, max 16 in transit per peer.\n\
  Relay / RPC initialblockdownload after catch-up: --min-chain-work + --max-tip-age (24h).",
        env!("CARGO_PKG_VERSION")
    )
}

#[doc(hidden)]
pub fn take_arg(args: &[OsString], i: &mut usize, flag: &str) -> Result<String, ExitCode> {
    *i += 1;
    if *i >= args.len() {
        eprintln!("error: {flag} requires a value");
        return Err(ExitCode::from(2));
    }
    let v = args[*i].to_string_lossy().into_owned();
    *i += 1;
    Ok(v)
}

#[doc(hidden)]
pub fn parse_log_level(raw: &str) -> Result<Option<Level>, ExitCode> {
    if raw.eq_ignore_ascii_case("off") || raw.eq_ignore_ascii_case("none") {
        Ok(None)
    } else if let Some(l) = Level::parse(raw) {
        Ok(Some(l))
    } else {
        eprintln!("error: bad --log-level `{raw}` (use error|warn|info|debug|trace|off)");
        Err(ExitCode::from(2))
    }
}

#[doc(hidden)]
pub fn is_bool_key(key: &str) -> bool {
    matches!(
        key,
        "sh_index"
            | "block_filter_index"
            | "prune_seqsigwit"
            | "datadir_hdd"
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
            | "rest"
            | "trusted"
            | "always_relay"
            | "relay"
            | "rpc"
    )
}

#[doc(hidden)]
pub fn is_optional_addr_key(key: &str) -> bool {
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

#[doc(hidden)]
pub fn looks_like_flag(s: &str) -> bool {
    s.starts_with("--") || matches!(s, "-h" | "-V")
}

#[doc(hidden)]
pub fn parse_cli_flag(
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

#[doc(hidden)]
pub fn print_run_err(e: &crate::error::NodeError) {
    match e {
        crate::error::NodeError::FutureTip | crate::error::NodeError::Init(_) => eprintln!("{e}"),
        crate::error::NodeError::Locked(_) => eprintln!("Error: {e}"),
        _ => error!("{e}"),
    }
}

#[doc(hidden)]
pub fn cli_apply_err(e: crate::error::NodeError) -> ExitCode {
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

#[doc(hidden)]
pub fn blocking_pool_size() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(rbitcoin_electrum::MIN_BLOCKING_POOL)
        .max(rbitcoin_electrum::MIN_BLOCKING_POOL)
}

#[doc(hidden)]
pub fn node_tokio_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(blocking_pool_size())
        .thread_name("tokio-rt-worker")
        .build()
}
