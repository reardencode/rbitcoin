use crate::config::NodeConfig;
use crate::inhibit::SuspendInhibit;
use crate::run::{run_node, run_p2p};
use rbitcoin_consensus::{default_milestone_height, ChainParams};
use rbitcoin_log::{self, error, info, warn, Level};
use rbitcoin_primitives::Network;
use rbitcoin_store::HeadScale;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

struct CliAccum {
    datadir: PathBuf,
    datadir_set: bool,
    datadir_cold: Option<PathBuf>,
    datadir_cold_set: bool,
    network: Network,
    network_set: bool,
    signet_challenge: Option<bitcoin::ScriptBuf>,
    signet_block_time: Option<u64>,
    smoke: bool,
    listen: Vec<SocketAddr>,
    electrum_listen: Option<SocketAddr>,
    esplora_listen: Option<SocketAddr>,
    shindex: bool,
    shindex_set: bool,
    sptweaks: bool,
    sptweaks_set: bool,
    rpc_listen: Option<SocketAddr>,
    rpc_user: Option<String>,
    rpc_password: Option<String>,
    rpc_work_queue: Option<usize>,
    connect: Vec<SocketAddr>,
    seednodes: Vec<String>,
    use_seeds: bool,
    seeds_set: bool,
    milestone_height: u32,
    milestone_set: bool,
    max_outbound: u32,
    max_outbound_set: bool,
    max_inbound: u32,
    max_inbound_set: bool,
    max_run_secs: Option<u64>,
    mempool_size_mb: Option<u64>,
    inhibit_suspend: bool,
    conf_path: Option<PathBuf>,
    log_level_cli: Option<Option<Level>>,
    api_log: Option<PathBuf>,
    asmap: Option<PathBuf>,
    uacomments: Vec<String>,
    test_activation_heights: Vec<(String, u32)>,
    persist_mempool: Option<bool>,
    whitelist: Vec<String>,
    blocksonly: Option<bool>,
    min_relay_fee_btc: Option<String>,
    mempool_expiry_hours: Option<u64>,
    startup_notify: Option<String>,
    alert_notify: Option<String>,
    permit_bare_multisig: Option<bool>,
    limit_cluster_count: Option<u32>,
    limit_cluster_size_kvb: Option<u32>,
    peer_timeout_secs: Option<u64>,
    minimum_chain_work: Option<[u8; 32]>,
    mock_time: Option<i64>,
    max_tip_age_secs: Option<u64>,
    block_version: Option<i32>,
    block_min_tx_fee_btc: Option<String>,
    external_ips: Vec<std::net::IpAddr>,
}

impl Default for CliAccum {
    fn default() -> Self {
        Self {
            datadir: NodeConfig::default_datadir(),
            datadir_set: false,
            datadir_cold: None,
            datadir_cold_set: false,
            network: Network::Mainnet,
            network_set: false,
            signet_challenge: None,
            signet_block_time: None,
            smoke: false,
            listen: Vec::new(),
            electrum_listen: None,
            esplora_listen: None,
            shindex: false,
            shindex_set: false,
            sptweaks: false,
            sptweaks_set: false,
            rpc_listen: None,
            rpc_user: None,
            rpc_password: None,
            rpc_work_queue: None,
            connect: Vec::new(),
            seednodes: Vec::new(),
            use_seeds: true,
            seeds_set: false,
            milestone_height: 0,
            milestone_set: false,
            max_outbound: 16,
            max_outbound_set: false,
            max_inbound: crate::config::DEFAULT_MAX_INBOUND,
            max_inbound_set: false,
            max_run_secs: None,
            mempool_size_mb: None,
            inhibit_suspend: false,
            conf_path: None,
            log_level_cli: None,
            api_log: None,
            asmap: None,
            uacomments: Vec::new(),
            test_activation_heights: Vec::new(),
            persist_mempool: None,
            whitelist: Vec::new(),
            blocksonly: None,
            min_relay_fee_btc: None,
            mempool_expiry_hours: None,
            startup_notify: None,
            alert_notify: None,
            permit_bare_multisig: None,
            limit_cluster_count: None,
            limit_cluster_size_kvb: None,
            peer_timeout_secs: None,
            minimum_chain_work: None,
            mock_time: None,
            max_tip_age_secs: None,
            block_version: None,
            block_min_tx_fee_btc: None,
            external_ips: Vec::new(),
        }
    }
}

/// Process entry used by `main` and high-level scenarios.
pub fn cli_main<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let mut i = 1usize;
    let mut acc = CliAccum::default();

    while i < args.len() {
        let a = args[i].to_string_lossy();
        match a.as_ref() {
            "--help" | "-h" => {
                eprintln!(
                    "rbitcoin-node {} — usage:\n\
  rbitcoin-node [--conf FILE] [--datadir PATH] [--datadir-cold PATH] [--network NET] \\\n\
    [--listen ADDR] [--connect ADDR]... [--electrum-listen ADDR] [--esplora-listen ADDR] \\\n\
    [--shindex] [--sptweaks] [--rpc-listen ADDR] [--rpcuser USER] [--rpcpassword PASS] \\\n\
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
RPC: --rpc-listen ADDR (default off); cookie under datadir/.cookie or --rpcuser/--rpcpassword.\n\
Cold files: --datadir-cold PATH puts Class A inwit.body/idx under PATH/store (HDD).\n\
  Default (flag omitted): hot and cold files both live under --datadir.\n\
Conf: --conf FILE (key=value; CLI overrides conf). See OPERATOR.md and docs/rpc.md.\n\
Advanced debug/IO knobs remain RBITCOIN_* env (not required for normal sync; preserved if CLI omits).\n\
IBD: up to 1024 concurrent getdata, max 16 in transit per peer.",
                    env!("CARGO_PKG_VERSION")
                );
                return ExitCode::SUCCESS;
            }
            "--version" | "-V" => {
                eprintln!("rbitcoin-node {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--smoke" => {
                acc.smoke = true;
                i += 1;
            }
            "--no-seeds" | "--noseeds" => {
                acc.use_seeds = false;
                acc.seeds_set = true;
                i += 1;
            }
            "--inhibit-suspend" => {
                acc.inhibit_suspend = true;
                i += 1;
            }
            "--conf" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --conf requires a path");
                    return ExitCode::from(2);
                }
                acc.conf_path = Some(PathBuf::from(&args[i]));
                i += 1;
            }
            "--datadir" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --datadir requires a value");
                    return ExitCode::from(2);
                }
                acc.datadir = PathBuf::from(&args[i]);
                acc.datadir_set = true;
                i += 1;
            }
            "--datadir-cold" | "--datadir_cold" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --datadir-cold requires a value");
                    return ExitCode::from(2);
                }
                acc.datadir_cold = Some(PathBuf::from(&args[i]));
                acc.datadir_cold_set = true;
                i += 1;
            }
            "--network" | "--chain" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --network requires a value");
                    return ExitCode::from(2);
                }
                match Network::parse(&args[i].to_string_lossy()) {
                    Ok(n) => {
                        acc.network = n;
                        acc.network_set = true;
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--signetchallenge" | "--signet-challenge" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --signetchallenge requires hexadecimal script bytes");
                    return ExitCode::from(2);
                }
                match crate::config::parse_signet_challenge(&args[i].to_string_lossy()) {
                    Ok(challenge) => acc.signet_challenge = Some(challenge),
                    Err(e) => {
                        eprintln!("error: bad --signetchallenge: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--signetblocktime" | "--signet-block-time" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --signetblocktime requires seconds");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse::<u64>() {
                    Ok(n) if n > 0 => acc.signet_block_time = Some(n),
                    Ok(_) => {
                        eprintln!("error: --signetblocktime must be greater than zero");
                        return ExitCode::from(2);
                    }
                    Err(e) => {
                        eprintln!("error: bad --signetblocktime: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--listen" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --listen requires a value");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse::<SocketAddr>() {
                    Ok(a) => acc.listen.push(a),
                    Err(e) => {
                        eprintln!("error: bad --listen: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--connect" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --connect requires a value");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse::<SocketAddr>() {
                    Ok(a) => acc.connect.push(a),
                    Err(e) => {
                        eprintln!("error: bad --connect: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--seednode" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --seednode requires a value");
                    return ExitCode::from(2);
                }
                let v = args[i].to_string_lossy().into_owned();
                if v.is_empty() {
                    eprintln!("error: --seednode requires a value");
                    return ExitCode::from(2);
                }
                acc.seednodes.push(v);
                i += 1;
            }
            "--electrum-listen" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --electrum-listen requires a value");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse::<SocketAddr>() {
                    Ok(a) => acc.electrum_listen = Some(a),
                    Err(e) => {
                        eprintln!("error: bad --electrum-listen: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--esplora-listen" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --esplora-listen requires a value");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse::<SocketAddr>() {
                    Ok(a) => acc.esplora_listen = Some(a),
                    Err(e) => {
                        eprintln!("error: bad --esplora-listen: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--shindex" | "-shindex" => {
                acc.shindex = true;
                acc.shindex_set = true;
                i += 1;
            }
            "--sptweaks" | "-sptweaks" => {
                acc.sptweaks = true;
                acc.sptweaks_set = true;
                i += 1;
            }
            "--rpc-listen" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --rpc-listen requires a value");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse::<SocketAddr>() {
                    Ok(a) => acc.rpc_listen = Some(a),
                    Err(e) => {
                        eprintln!("error: bad --rpc-listen: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--rpcuser" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --rpcuser requires a value");
                    return ExitCode::from(2);
                }
                acc.rpc_user = Some(args[i].to_string_lossy().into_owned());
                i += 1;
            }
            "--rpcpassword" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --rpcpassword requires a value");
                    return ExitCode::from(2);
                }
                acc.rpc_password = Some(args[i].to_string_lossy().into_owned());
                i += 1;
            }
            other if other.starts_with("--rpcworkqueue=") => {
                match other["--rpcworkqueue=".len()..].parse::<usize>() {
                    Ok(n) if n > 0 => acc.rpc_work_queue = Some(n),
                    _ => {
                        eprintln!("error: bad --rpcworkqueue");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--rpcworkqueue" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --rpcworkqueue requires a depth");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse::<usize>() {
                    Ok(n) if n > 0 => acc.rpc_work_queue = Some(n),
                    _ => {
                        eprintln!("error: bad --rpcworkqueue");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--mempool-size-mb" | "--maxmempool" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --mempool-size-mb requires a number");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse::<u64>() {
                    Ok(n) if n > 0 => acc.mempool_size_mb = Some(n),
                    Ok(_) => {
                        eprintln!("error: --mempool-size-mb must be >= 1");
                        return ExitCode::from(2);
                    }
                    Err(e) => {
                        eprintln!("error: bad --mempool-size-mb: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--milestone" | "--assumevalid-height" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --milestone requires a height");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse::<u32>() {
                    Ok(h) => {
                        acc.milestone_height = h;
                        acc.milestone_set = true;
                    }
                    Err(e) => {
                        eprintln!("error: bad --milestone: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--max-outbound" | "--maxoutbound" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --max-outbound requires a number");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse::<u32>() {
                    Ok(n) if n > 0 => {
                        acc.max_outbound = n;
                        acc.max_outbound_set = true;
                    }
                    Ok(_) => {
                        eprintln!("error: --max-outbound must be >= 1");
                        return ExitCode::from(2);
                    }
                    Err(e) => {
                        eprintln!("error: bad --max-outbound: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--max-inbound" | "--maxinbound" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --maxinbound requires a number");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse::<u32>() {
                    Ok(n) if n > 0 => {
                        acc.max_inbound = n;
                        acc.max_inbound_set = true;
                    }
                    Ok(_) => {
                        eprintln!("error: --maxinbound must be >= 1");
                        return ExitCode::from(2);
                    }
                    Err(e) => {
                        eprintln!("error: bad --maxinbound: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--maxconnections" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --maxconnections requires a number");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse::<u32>() {
                    Ok(n) if n > 0 => {
                        acc.max_inbound = crate::config::inbound_from_maxconnections(n);
                        acc.max_inbound_set = true;
                    }
                    Ok(_) => {
                        eprintln!("error: --maxconnections must be >= 1");
                        return ExitCode::from(2);
                    }
                    Err(e) => {
                        eprintln!("error: bad --maxconnections: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--max-run-secs" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --max-run-secs requires a number");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse::<u64>() {
                    Ok(n) => acc.max_run_secs = Some(n),
                    Err(e) => {
                        eprintln!("error: bad --max-run-secs: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--uacomment" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --uacomment requires a value");
                    return ExitCode::from(2);
                }
                acc.uacomments.push(args[i].to_string_lossy().into_owned());
                i += 1;
            }
            other if other.starts_with("--uacomment=") => {
                acc.uacomments
                    .push(other["--uacomment=".len()..].to_string());
                i += 1;
            }
            "--testactivationheight" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --testactivationheight requires name@height");
                    return ExitCode::from(2);
                }
                let spec = args[i].to_string_lossy();
                match ChainParams::parse_test_activation_height(&spec) {
                    Ok((n, h)) => acc.test_activation_heights.push((n.to_string(), h)),
                    Err(e) => {
                        eprintln!("error: --testactivationheight: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            other if other.starts_with("--testactivationheight=") => {
                let spec = &other["--testactivationheight=".len()..];
                match ChainParams::parse_test_activation_height(spec) {
                    Ok((n, h)) => acc.test_activation_heights.push((n.to_string(), h)),
                    Err(e) => {
                        eprintln!("error: --testactivationheight: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--blocksonly" => {
                acc.blocksonly = Some(true);
                i += 1;
            }
            other if other.starts_with("--blocksonly=") => {
                match parse_cli_bool(&other["--blocksonly=".len()..]) {
                    Some(b) => acc.blocksonly = Some(b),
                    None => {
                        eprintln!("error: bad --blocksonly value");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--persistmempool" => {
                acc.persist_mempool = Some(true);
                i += 1;
            }
            other if other.starts_with("--persistmempool=") => {
                match parse_cli_bool(&other["--persistmempool=".len()..]) {
                    Some(b) => acc.persist_mempool = Some(b),
                    None => {
                        eprintln!("error: bad --persistmempool value");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--permitbaremultisig" => {
                acc.permit_bare_multisig = Some(true);
                i += 1;
            }
            other if other.starts_with("--permitbaremultisig=") => {
                match parse_cli_bool(&other["--permitbaremultisig=".len()..]) {
                    Some(b) => acc.permit_bare_multisig = Some(b),
                    None => {
                        eprintln!("error: bad --permitbaremultisig value");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            other if other.starts_with("--whitelist=") => {
                let v = &other["--whitelist=".len()..];
                if !v.is_empty() {
                    acc.whitelist.push(v.to_string());
                }
                i += 1;
            }
            "--whitelist" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --whitelist requires a value");
                    return ExitCode::from(2);
                }
                acc.whitelist.push(args[i].to_string_lossy().into_owned());
                i += 1;
            }
            other if other.starts_with("--minrelaytxfee=") => {
                acc.min_relay_fee_btc = Some(other["--minrelaytxfee=".len()..].to_string());
                i += 1;
            }
            "--minrelaytxfee" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --minrelaytxfee requires a value");
                    return ExitCode::from(2);
                }
                acc.min_relay_fee_btc = Some(args[i].to_string_lossy().into_owned());
                i += 1;
            }
            other if other.starts_with("--mempoolexpiry=") => {
                match other["--mempoolexpiry=".len()..].parse::<u64>() {
                    Ok(n) => acc.mempool_expiry_hours = Some(n.max(1)),
                    Err(e) => {
                        eprintln!("error: bad --mempoolexpiry: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--mempoolexpiry" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --mempoolexpiry requires a value");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse::<u64>() {
                    Ok(n) => acc.mempool_expiry_hours = Some(n.max(1)),
                    Err(e) => {
                        eprintln!("error: bad --mempoolexpiry: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            other if other.starts_with("--startupnotify=") => {
                acc.startup_notify = Some(other["--startupnotify=".len()..].to_string());
                i += 1;
            }
            "--startupnotify" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --startupnotify requires a value");
                    return ExitCode::from(2);
                }
                acc.startup_notify = Some(args[i].to_string_lossy().into_owned());
                i += 1;
            }
            other if other.starts_with("--alertnotify=") => {
                acc.alert_notify = Some(other["--alertnotify=".len()..].to_string());
                i += 1;
            }
            "--alertnotify" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --alertnotify requires a value");
                    return ExitCode::from(2);
                }
                acc.alert_notify = Some(args[i].to_string_lossy().into_owned());
                i += 1;
            }
            other if other.starts_with("--limitclustercount=") => {
                match other["--limitclustercount=".len()..].parse() {
                    Ok(n) => acc.limit_cluster_count = Some(n),
                    Err(e) => {
                        eprintln!("error: bad --limitclustercount: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--limitclustercount" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --limitclustercount requires a number");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse() {
                    Ok(n) => acc.limit_cluster_count = Some(n),
                    Err(e) => {
                        eprintln!("error: bad --limitclustercount: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            other if other.starts_with("--limitclustersize=") => {
                match other["--limitclustersize=".len()..].parse() {
                    Ok(n) => acc.limit_cluster_size_kvb = Some(n),
                    Err(e) => {
                        eprintln!("error: bad --limitclustersize: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--limitclustersize" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --limitclustersize requires a number");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse() {
                    Ok(n) => acc.limit_cluster_size_kvb = Some(n),
                    Err(e) => {
                        eprintln!("error: bad --limitclustersize: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            other if other.starts_with("--seednode=") => {
                let v = other["--seednode=".len()..].to_string();
                if v.is_empty() {
                    eprintln!("error: --seednode requires a value");
                    return ExitCode::from(2);
                }
                acc.seednodes.push(v);
                i += 1;
            }
            other if other.starts_with("--externalip=") => {
                match other["--externalip=".len()..].parse() {
                    Ok(ip) => acc.external_ips.push(ip),
                    Err(e) => {
                        eprintln!("error: bad --externalip: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--externalip" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --externalip requires an address");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse() {
                    Ok(ip) => acc.external_ips.push(ip),
                    Err(e) => {
                        eprintln!("error: bad --externalip: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            other if other.starts_with("--peertimeout=") => {
                match other["--peertimeout=".len()..].parse() {
                    Ok(0) => {
                        eprintln!("Error: peertimeout must be a positive integer.");
                        return ExitCode::from(1);
                    }
                    Ok(n) => acc.peer_timeout_secs = Some(n),
                    Err(e) => {
                        eprintln!("error: bad --peertimeout: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--peertimeout" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --peertimeout requires a number");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse() {
                    Ok(0) => {
                        eprintln!("Error: peertimeout must be a positive integer.");
                        return ExitCode::from(1);
                    }
                    Ok(n) => acc.peer_timeout_secs = Some(n),
                    Err(e) => {
                        eprintln!("error: bad --peertimeout: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            other if other.starts_with("--mocktime=") => {
                match other["--mocktime=".len()..].parse::<i64>() {
                    Ok(n) if n >= 0 => acc.mock_time = Some(n),
                    _ => {
                        eprintln!("error: bad --mocktime");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--mocktime" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --mocktime requires a unix time");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse::<i64>() {
                    Ok(n) if n >= 0 => acc.mock_time = Some(n),
                    _ => {
                        eprintln!("error: bad --mocktime");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            other if other.starts_with("--maxtipage=") => {
                match other["--maxtipage=".len()..].parse::<i64>() {
                    Ok(n) if n >= 0 => acc.max_tip_age_secs = Some(n as u64),
                    _ => {
                        eprintln!("error: bad --maxtipage");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--maxtipage" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --maxtipage requires a number of seconds");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse::<i64>() {
                    Ok(n) if n >= 0 => acc.max_tip_age_secs = Some(n as u64),
                    _ => {
                        eprintln!("error: bad --maxtipage");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            other if other.starts_with("--blockversion=") => {
                match other["--blockversion=".len()..].parse::<i32>() {
                    Ok(n) => acc.block_version = Some(n),
                    Err(e) => {
                        eprintln!("error: bad --blockversion: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--blockversion" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --blockversion requires an integer");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse::<i32>() {
                    Ok(n) => acc.block_version = Some(n),
                    Err(e) => {
                        eprintln!("error: bad --blockversion: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            other if other.starts_with("--blockmintxfee=") => {
                acc.block_min_tx_fee_btc = Some(other["--blockmintxfee=".len()..].to_string());
                i += 1;
            }
            "--blockmintxfee" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --blockmintxfee requires a value");
                    return ExitCode::from(2);
                }
                acc.block_min_tx_fee_btc = Some(args[i].to_string_lossy().into_owned());
                i += 1;
            }
            other if other.starts_with("--minimumchainwork=") => {
                match crate::config::parse_minimum_chain_work(&other["--minimumchainwork=".len()..])
                {
                    Ok(w) => acc.minimum_chain_work = Some(w),
                    Err(e) => {
                        eprintln!("Error: {e}");
                        return ExitCode::from(1);
                    }
                }
                i += 1;
            }
            "--minimumchainwork" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --minimumchainwork requires a hex value");
                    return ExitCode::from(2);
                }
                match crate::config::parse_minimum_chain_work(&args[i].to_string_lossy()) {
                    Ok(w) => acc.minimum_chain_work = Some(w),
                    Err(e) => {
                        eprintln!("Error: {e}");
                        return ExitCode::from(1);
                    }
                }
                i += 1;
            }
            other if other.starts_with("--maxconnections=") => {
                match other["--maxconnections=".len()..].parse::<u32>() {
                    Ok(n) if n > 0 => {
                        acc.max_inbound = crate::config::inbound_from_maxconnections(n);
                        acc.max_inbound_set = true;
                    }
                    Ok(_) => {
                        eprintln!("error: --maxconnections must be >= 1");
                        return ExitCode::from(2);
                    }
                    Err(e) => {
                        eprintln!("error: bad --maxconnections: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            other if other.starts_with("--maxinbound=") || other.starts_with("--max-inbound=") => {
                let raw = other.split_once('=').map(|(_, v)| v).unwrap_or("");
                match raw.parse::<u32>() {
                    Ok(n) if n > 0 => {
                        acc.max_inbound = n;
                        acc.max_inbound_set = true;
                    }
                    Ok(_) => {
                        eprintln!("error: --maxinbound must be >= 1");
                        return ExitCode::from(2);
                    }
                    Err(e) => {
                        eprintln!("error: bad --maxinbound: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--api-log" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --api-log requires a path");
                    return ExitCode::from(2);
                }
                acc.api_log = Some(PathBuf::from(&args[i]));
                i += 1;
            }
            "--asmap" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --asmap requires a path");
                    return ExitCode::from(2);
                }
                acc.asmap = Some(PathBuf::from(&args[i]));
                i += 1;
            }
            "--log-level" => {
                i += 1;
                if i >= args.len() {
                    eprintln!(
                        "error: --log-level requires a value (error|warn|info|debug|trace|off)"
                    );
                    return ExitCode::from(2);
                }
                let raw = args[i].to_string_lossy();
                if raw.eq_ignore_ascii_case("off") || raw.eq_ignore_ascii_case("none") {
                    acc.log_level_cli = Some(None);
                } else if let Some(l) = Level::parse(&raw) {
                    acc.log_level_cli = Some(Some(l));
                } else {
                    eprintln!(
                        "error: bad --log-level `{raw}` (use error|warn|info|debug|trace|off)"
                    );
                    return ExitCode::from(2);
                }
                i += 1;
            }
            other => {
                eprintln!("error: unknown argument `{other}`");
                return ExitCode::from(2);
            }
        }
    }

    // Conf file first (if any); CLI flags below override.
    let mut config = NodeConfig::default();
    if let Some(ref cp) = acc.conf_path {
        if let Err(e) = config.merge_conf_file(cp) {
            // Logging not ready; stderr is fine.
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    }
    if !acc.uacomments.is_empty() {
        config.uacomments.extend(acc.uacomments);
    }
    // Validate UA before any log init so feature_uacomment can fullmatch stderr.
    if let Err(e) =
        rbitcoin_primitives::rbitcoin_subversion(env!("CARGO_PKG_VERSION"), &config.uacomments)
    {
        eprintln!("{e}");
        return ExitCode::from(1);
    }

    // Logging: CLI --log-level > conf log_level > RBITCOIN_LOG / RUST_LOG > Info.
    match acc.log_level_cli {
        Some(Some(level)) => rbitcoin_log::init(level),
        Some(None) => rbitcoin_log::init_off(),
        None => {
            if let Some(ref raw) = config.conf_log_level {
                if raw.eq_ignore_ascii_case("off") || raw.eq_ignore_ascii_case("none") {
                    rbitcoin_log::init_off();
                } else if let Some(l) = Level::parse(raw) {
                    rbitcoin_log::init(l);
                } else {
                    eprintln!(
                        "error: conf log_level `{raw}` invalid (use error|warn|info|debug|trace|off)"
                    );
                    return ExitCode::from(2);
                }
            } else if !rbitcoin_log::init_from_env() {
                rbitcoin_log::init(Level::Info);
            }
        }
    }

    if let Some(p) = acc.api_log {
        config.api_log = Some(p);
    }
    if let Some(p) = acc.asmap {
        config.asmap = Some(p);
    }
    if let Some(ref p) = config.api_log {
        if let Err(e) = rbitcoin_log::init_api_log(p) {
            eprintln!("error: --api-log {}: {e}", p.display());
            return ExitCode::from(2);
        }
        rbitcoin_log::info!("api-log: {}", p.display());
    }

    // 256-way sharded heads need 1k+ FDs; raise soft NOFILE before store open.
    let (soft, hard) = rbitcoin_store::ensure_nofile_budget();
    if soft > 0 {
        rbitcoin_log::debug!("node: RLIMIT_NOFILE soft={soft} hard={hard}");
    }

    if acc.datadir_set {
        config.datadir.path = acc.datadir;
    }
    if acc.datadir_cold_set {
        config.datadir.cold = acc.datadir_cold;
    }
    if acc.network_set {
        config.network = acc.network;
    }
    if let Some(challenge) = acc.signet_challenge {
        config.signet_challenge = Some(challenge);
    }
    if acc.signet_block_time.is_some() {
        config.signet_block_time = acc.signet_block_time;
    }
    if let Some((first, rest)) = acc.listen.split_first() {
        config.listen.p2p = Some(*first);
        config.listen.p2p_extra.extend(rest.iter().copied());
    }
    if let Some(a) = acc.electrum_listen {
        config.listen.electrum = Some(a);
    }
    if let Some(a) = acc.esplora_listen {
        config.listen.esplora = Some(a);
    }
    if acc.shindex_set {
        config.shindex = acc.shindex;
    }
    if acc.sptweaks_set {
        config.sptweaks = acc.sptweaks;
    }
    if let Some(a) = acc.rpc_listen {
        config.rpc.listen = Some(a);
    }
    if let Some(u) = acc.rpc_user {
        config.rpc.user = Some(u);
    }
    if let Some(p) = acc.rpc_password {
        config.rpc.password = Some(p);
    }
    if let Some(n) = acc.rpc_work_queue {
        config.rpc.work_queue = Some(n);
    }
    if !acc.connect.is_empty() {
        config.listen.connect = acc.connect;
    }
    if !acc.seednodes.is_empty() {
        config.listen.seednodes = acc.seednodes;
    }
    if acc.seeds_set {
        config.listen.use_seeds = acc.use_seeds;
    }
    config.smoke = acc.smoke;
    // Milestone: CLI > conf > network default (assumevalid-style).
    if acc.milestone_set {
        config.milestone_height = acc.milestone_height;
    } else if config.milestone_height == 0 {
        config.milestone_height = default_milestone_height(config.network);
    }
    if acc.max_outbound_set {
        config.listen.max_outbound = acc.max_outbound;
    }
    if acc.max_inbound_set {
        config.listen.max_inbound = acc.max_inbound;
        config.listen.max_inbound_explicit = true;
    }
    config.inhibit_suspend = acc.inhibit_suspend;
    // Map MiB → weight units (1 MiB ≈ 1e6 WU for budget purposes).
    if let Some(mb) = acc.mempool_size_mb {
        config.mempool.max_weight = mb.saturating_mul(1_000_000);
    }
    if !acc.test_activation_heights.is_empty() {
        config
            .test_activation_heights
            .extend(acc.test_activation_heights);
    }
    if let Some(b) = acc.persist_mempool {
        config.mempool.persist = b;
    }
    if !acc.whitelist.is_empty() {
        config.whitelist.extend(acc.whitelist);
    }
    if let Some(b) = acc.blocksonly {
        config.mempool.blocksonly = b;
    }
    if let Some(s) = acc.min_relay_fee_btc {
        config.mempool.min_relay_fee_btc = Some(s);
    }
    if let Some(h) = acc.mempool_expiry_hours {
        config.mempool.expiry_hours = Some(h);
    }
    if let Some(s) = acc.startup_notify {
        config.startup_notify = Some(s);
    }
    if let Some(s) = acc.alert_notify {
        config.alert_notify = Some(s);
    }
    if let Some(b) = acc.permit_bare_multisig {
        config.mempool.permit_bare_multisig = b;
    }
    if let Some(n) = acc.limit_cluster_count {
        config.mempool.limit_cluster_count = Some(n);
    }
    if let Some(n) = acc.limit_cluster_size_kvb {
        config.mempool.limit_cluster_size_kvb = Some(n);
    }
    if let Some(n) = acc.peer_timeout_secs {
        config.listen.peer_timeout_secs = Some(n);
    }
    if let Some(w) = acc.minimum_chain_work {
        config.minimum_chain_work = Some(w);
    }
    if let Some(t) = acc.mock_time {
        config.mock_time = Some(t);
    }
    if let Some(n) = acc.max_tip_age_secs {
        config.max_tip_age_secs = Some(n);
    }
    if let Some(v) = acc.block_version {
        config.block_version = Some(v);
    }
    if let Some(s) = acc.block_min_tx_fee_btc {
        config.block_min_tx_fee_btc = Some(s);
    }
    if !acc.external_ips.is_empty() {
        config.listen.external_ips.extend(acc.external_ips);
    }

    // Unstable env is an input when CLI/conf omitted inbound — never set_var.
    config.absorb_inbound_env();

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
    if acc.max_run_secs.is_some() {
        config.max_run_secs = acc.max_run_secs;
    }

    if let Err(e) = config.ensure_datadir() {
        error!("{e}");
        return ExitCode::FAILURE;
    }

    if acc.smoke {
        config.head_scale = HeadScale::Tiny;
        match run_node(config) {
            Ok(handle) => {
                info!(
                    "rbitcoin-node {} on {} datadir={}",
                    env!("CARGO_PKG_VERSION"),
                    handle.network_name(),
                    handle.config.datadir.display()
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
        // Peer sessions can still be in spawn_blocking / CPU header walks
        // after `clean exit`. Dropping the runtime would wait on them.
        rt.shutdown_timeout(std::time::Duration::from_secs(2));
        code
    }
}

/// Tokio runtime for `run_p2p`: cap `spawn_blocking` at nCPU (min 4).
/// Default `Runtime::new()` allows 512 blocking threads.
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

fn parse_cli_bool(v: &str) -> Option<bool> {
    match v {
        "" | "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OPERATOR_ENV_TEST_LOCK;
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
