use crate::config::NodeConfig;
use crate::inhibit::SuspendInhibit;
use crate::run::{run_node, run_p2p};
use rbitcoin_consensus::{default_milestone_height, ChainParams};
use rbitcoin_log::{self, error, info, warn, Level};
use rbitcoin_primitives::Network;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

/// Process entry used by `main` and high-level scenarios.
pub fn cli_main<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let mut i = 1usize;
    let mut datadir = NodeConfig::default_datadir();
    let mut datadir_set = false;
    let mut datadir_cold: Option<PathBuf> = None;
    let mut datadir_cold_set = false;
    let mut network = Network::Mainnet;
    let mut network_set = false;
    let mut signet_challenge = None;
    let mut signet_block_time = None;
    let mut smoke = false;
    let mut listen: Vec<SocketAddr> = Vec::new();
    let mut electrum_listen: Option<SocketAddr> = None;
    let mut esplora_listen: Option<SocketAddr> = None;
    let mut shindex = false;
    let mut shindex_set = false;
    let mut sptweaks = false;
    let mut sptweaks_set = false;
    let mut rpc_listen: Option<SocketAddr> = None;
    let mut rpc_user: Option<String> = None;
    let mut rpc_password: Option<String> = None;
    let mut rpc_work_queue: Option<usize> = None;
    let mut connect: Vec<SocketAddr> = Vec::new();
    let mut seednodes: Vec<String> = Vec::new();
    let mut use_seeds = true;
    let mut seeds_set = false;
    let mut milestone_height = 0u32;
    let mut milestone_set = false;
    let mut max_outbound = 16u32;
    let mut max_outbound_set = false;
    let mut max_inbound = crate::config::DEFAULT_MAX_INBOUND;
    let mut max_inbound_set = false;
    let mut max_run_secs: Option<u64> = None;
    let mut mempool_size_mb: Option<u64> = None;
    let mut inhibit_suspend = false;
    let mut conf_path: Option<PathBuf> = None;
    // None = env/default; Some(None) = off; Some(Some(level)) = explicit level.
    let mut log_level_cli: Option<Option<Level>> = None;
    let mut api_log: Option<PathBuf> = None;
    let mut uacomments: Vec<String> = Vec::new();
    let mut test_activation_heights: Vec<(String, u32)> = Vec::new();
    let mut persist_mempool: Option<bool> = None;
    let mut whitelist: Vec<String> = Vec::new();
    let mut blocksonly: Option<bool> = None;
    let mut min_relay_fee_btc: Option<String> = None;
    let mut mempool_expiry_hours: Option<u64> = None;
    let mut startup_notify: Option<String> = None;
    let mut alert_notify: Option<String> = None;
    let mut permit_bare_multisig: Option<bool> = None;
    let mut limit_cluster_count: Option<u32> = None;
    let mut limit_cluster_size_kvb: Option<u32> = None;
    let mut peer_timeout_secs: Option<u64> = None;
    let mut minimum_chain_work: Option<[u8; 32]> = None;
    let mut mock_time: Option<i64> = None;
    let mut max_tip_age_secs: Option<u64> = None;
    let mut block_version: Option<i32> = None;
    let mut block_min_tx_fee_btc: Option<String> = None;

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
    [--minimumchainwork HEX] \\\n\
    [--max-run-secs N] [--log-level LEVEL] [--api-log PATH] [--uacomment STR] \\\n\
    [--no-seeds] [--smoke] [--inhibit-suspend]\n\n\
Networks: mainnet|testnet|signet|regtest\n\
Custom Signet: --signetchallenge HEX [--signetblocktime SECONDS].\n\
Log level: error|warn|info|debug|trace|off (CLI > conf log_level > RBITCOIN_LOG / RUST_LOG).\n\
API log: --api-log PATH writes one JSON line per Electrum/Esplora/RPC call (also TRACE `api:`).\n\
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
                smoke = true;
                i += 1;
            }
            "--no-seeds" | "--noseeds" => {
                use_seeds = false;
                seeds_set = true;
                i += 1;
            }
            "--inhibit-suspend" => {
                inhibit_suspend = true;
                i += 1;
            }
            "--conf" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --conf requires a path");
                    return ExitCode::from(2);
                }
                conf_path = Some(PathBuf::from(&args[i]));
                i += 1;
            }
            "--datadir" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --datadir requires a value");
                    return ExitCode::from(2);
                }
                datadir = PathBuf::from(&args[i]);
                datadir_set = true;
                i += 1;
            }
            "--datadir-cold" | "--datadir_cold" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --datadir-cold requires a value");
                    return ExitCode::from(2);
                }
                datadir_cold = Some(PathBuf::from(&args[i]));
                datadir_cold_set = true;
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
                        network = n;
                        network_set = true;
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
                    Ok(challenge) => signet_challenge = Some(challenge),
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
                    Ok(n) if n > 0 => signet_block_time = Some(n),
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
                    Ok(a) => listen.push(a),
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
                    Ok(a) => connect.push(a),
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
                seednodes.push(v);
                i += 1;
            }
            "--electrum-listen" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --electrum-listen requires a value");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse::<SocketAddr>() {
                    Ok(a) => electrum_listen = Some(a),
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
                    Ok(a) => esplora_listen = Some(a),
                    Err(e) => {
                        eprintln!("error: bad --esplora-listen: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--shindex" | "-shindex" => {
                shindex = true;
                shindex_set = true;
                i += 1;
            }
            "--sptweaks" | "-sptweaks" => {
                sptweaks = true;
                sptweaks_set = true;
                i += 1;
            }
            "--rpc-listen" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --rpc-listen requires a value");
                    return ExitCode::from(2);
                }
                match args[i].to_string_lossy().parse::<SocketAddr>() {
                    Ok(a) => rpc_listen = Some(a),
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
                rpc_user = Some(args[i].to_string_lossy().into_owned());
                i += 1;
            }
            "--rpcpassword" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --rpcpassword requires a value");
                    return ExitCode::from(2);
                }
                rpc_password = Some(args[i].to_string_lossy().into_owned());
                i += 1;
            }
            other if other.starts_with("--rpcworkqueue=") => {
                match other["--rpcworkqueue=".len()..].parse::<usize>() {
                    Ok(n) if n > 0 => rpc_work_queue = Some(n),
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
                    Ok(n) if n > 0 => rpc_work_queue = Some(n),
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
                    Ok(n) if n > 0 => mempool_size_mb = Some(n),
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
                        milestone_height = h;
                        milestone_set = true;
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
                        max_outbound = n;
                        max_outbound_set = true;
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
                        max_inbound = n;
                        max_inbound_set = true;
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
                        max_inbound = crate::config::inbound_from_maxconnections(n);
                        max_inbound_set = true;
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
                    Ok(n) => max_run_secs = Some(n),
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
                uacomments.push(args[i].to_string_lossy().into_owned());
                i += 1;
            }
            other if other.starts_with("--uacomment=") => {
                uacomments.push(other["--uacomment=".len()..].to_string());
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
                    Ok((n, h)) => test_activation_heights.push((n.to_string(), h)),
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
                    Ok((n, h)) => test_activation_heights.push((n.to_string(), h)),
                    Err(e) => {
                        eprintln!("error: --testactivationheight: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--blocksonly" => {
                blocksonly = Some(true);
                i += 1;
            }
            other if other.starts_with("--blocksonly=") => {
                match parse_cli_bool(&other["--blocksonly=".len()..]) {
                    Some(b) => blocksonly = Some(b),
                    None => {
                        eprintln!("error: bad --blocksonly value");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--persistmempool" => {
                persist_mempool = Some(true);
                i += 1;
            }
            other if other.starts_with("--persistmempool=") => {
                match parse_cli_bool(&other["--persistmempool=".len()..]) {
                    Some(b) => persist_mempool = Some(b),
                    None => {
                        eprintln!("error: bad --persistmempool value");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            "--permitbaremultisig" => {
                permit_bare_multisig = Some(true);
                i += 1;
            }
            other if other.starts_with("--permitbaremultisig=") => {
                match parse_cli_bool(&other["--permitbaremultisig=".len()..]) {
                    Some(b) => permit_bare_multisig = Some(b),
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
                    whitelist.push(v.to_string());
                }
                i += 1;
            }
            "--whitelist" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --whitelist requires a value");
                    return ExitCode::from(2);
                }
                whitelist.push(args[i].to_string_lossy().into_owned());
                i += 1;
            }
            other if other.starts_with("--minrelaytxfee=") => {
                min_relay_fee_btc = Some(other["--minrelaytxfee=".len()..].to_string());
                i += 1;
            }
            "--minrelaytxfee" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --minrelaytxfee requires a value");
                    return ExitCode::from(2);
                }
                min_relay_fee_btc = Some(args[i].to_string_lossy().into_owned());
                i += 1;
            }
            other if other.starts_with("--mempoolexpiry=") => {
                match other["--mempoolexpiry=".len()..].parse::<u64>() {
                    Ok(n) => mempool_expiry_hours = Some(n.max(1)),
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
                    Ok(n) => mempool_expiry_hours = Some(n.max(1)),
                    Err(e) => {
                        eprintln!("error: bad --mempoolexpiry: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            other if other.starts_with("--startupnotify=") => {
                startup_notify = Some(other["--startupnotify=".len()..].to_string());
                i += 1;
            }
            "--startupnotify" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --startupnotify requires a value");
                    return ExitCode::from(2);
                }
                startup_notify = Some(args[i].to_string_lossy().into_owned());
                i += 1;
            }
            other if other.starts_with("--alertnotify=") => {
                alert_notify = Some(other["--alertnotify=".len()..].to_string());
                i += 1;
            }
            "--alertnotify" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --alertnotify requires a value");
                    return ExitCode::from(2);
                }
                alert_notify = Some(args[i].to_string_lossy().into_owned());
                i += 1;
            }
            other if other.starts_with("--limitclustercount=") => {
                match other["--limitclustercount=".len()..].parse() {
                    Ok(n) => limit_cluster_count = Some(n),
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
                    Ok(n) => limit_cluster_count = Some(n),
                    Err(e) => {
                        eprintln!("error: bad --limitclustercount: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            other if other.starts_with("--limitclustersize=") => {
                match other["--limitclustersize=".len()..].parse() {
                    Ok(n) => limit_cluster_size_kvb = Some(n),
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
                    Ok(n) => limit_cluster_size_kvb = Some(n),
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
                seednodes.push(v);
                i += 1;
            }
            other if other.starts_with("--peertimeout=") => {
                match other["--peertimeout=".len()..].parse() {
                    Ok(n) => peer_timeout_secs = Some(n),
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
                    Ok(n) => peer_timeout_secs = Some(n),
                    Err(e) => {
                        eprintln!("error: bad --peertimeout: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            other if other.starts_with("--mocktime=") => {
                match other["--mocktime=".len()..].parse::<i64>() {
                    Ok(n) if n >= 0 => mock_time = Some(n),
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
                    Ok(n) if n >= 0 => mock_time = Some(n),
                    _ => {
                        eprintln!("error: bad --mocktime");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            other if other.starts_with("--maxtipage=") => {
                match other["--maxtipage=".len()..].parse::<i64>() {
                    Ok(n) if n >= 0 => max_tip_age_secs = Some(n as u64),
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
                    Ok(n) if n >= 0 => max_tip_age_secs = Some(n as u64),
                    _ => {
                        eprintln!("error: bad --maxtipage");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            other if other.starts_with("--blockversion=") => {
                match other["--blockversion=".len()..].parse::<i32>() {
                    Ok(n) => block_version = Some(n),
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
                    Ok(n) => block_version = Some(n),
                    Err(e) => {
                        eprintln!("error: bad --blockversion: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            other if other.starts_with("--blockmintxfee=") => {
                block_min_tx_fee_btc = Some(other["--blockmintxfee=".len()..].to_string());
                i += 1;
            }
            "--blockmintxfee" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --blockmintxfee requires a value");
                    return ExitCode::from(2);
                }
                block_min_tx_fee_btc = Some(args[i].to_string_lossy().into_owned());
                i += 1;
            }
            other if other.starts_with("--minimumchainwork=") => {
                match crate::config::parse_minimum_chain_work(&other["--minimumchainwork=".len()..])
                {
                    Ok(w) => minimum_chain_work = Some(w),
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
                    Ok(w) => minimum_chain_work = Some(w),
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
                        max_inbound = crate::config::inbound_from_maxconnections(n);
                        max_inbound_set = true;
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
                let raw = other
                    .split_once('=')
                    .map(|(_, v)| v)
                    .unwrap_or("");
                match raw.parse::<u32>() {
                    Ok(n) if n > 0 => {
                        max_inbound = n;
                        max_inbound_set = true;
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
                api_log = Some(PathBuf::from(&args[i]));
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
                    log_level_cli = Some(None);
                } else if let Some(l) = Level::parse(&raw) {
                    log_level_cli = Some(Some(l));
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
    if let Some(ref cp) = conf_path {
        if let Err(e) = config.merge_conf_file(cp) {
            // Logging not ready; stderr is fine.
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    }
    if !uacomments.is_empty() {
        config.uacomments.extend(uacomments);
    }
    // Validate UA before any log init so feature_uacomment can fullmatch stderr.
    if let Err(e) =
        rbitcoin_primitives::rbitcoin_subversion(env!("CARGO_PKG_VERSION"), &config.uacomments)
    {
        eprintln!("{e}");
        return ExitCode::from(1);
    }

    // Logging: CLI --log-level > conf log_level > RBITCOIN_LOG / RUST_LOG > Info.
    match log_level_cli {
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

    if let Some(p) = api_log {
        config.api_log = Some(p);
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

    if datadir_set {
        config.datadir = datadir;
    }
    if datadir_cold_set {
        config.datadir_cold = datadir_cold;
    }
    if network_set {
        config.network = network;
    }
    if let Some(challenge) = signet_challenge {
        config.signet_challenge = Some(challenge);
    }
    if signet_block_time.is_some() {
        config.signet_block_time = signet_block_time;
    }
    if let Some((first, rest)) = listen.split_first() {
        config.p2p_listen = Some(*first);
        config.p2p_extra_listens.extend(rest.iter().copied());
    }
    if let Some(a) = electrum_listen {
        config.electrum_listen = Some(a);
    }
    if let Some(a) = esplora_listen {
        config.esplora_listen = Some(a);
    }
    if shindex_set {
        config.shindex = shindex;
    }
    if sptweaks_set {
        config.sptweaks = sptweaks;
    }
    if let Some(a) = rpc_listen {
        config.rpc_listen = Some(a);
    }
    if let Some(u) = rpc_user {
        config.rpc_user = Some(u);
    }
    if let Some(p) = rpc_password {
        config.rpc_password = Some(p);
    }
    if let Some(n) = rpc_work_queue {
        config.rpc_work_queue = Some(n);
    }
    if !connect.is_empty() {
        config.connect = connect;
    }
    if !seednodes.is_empty() {
        config.seednodes = seednodes;
    }
    if seeds_set {
        config.use_seeds = use_seeds;
    }
    config.smoke = smoke;
    // Milestone: CLI > conf > network default (assumevalid-style).
    if milestone_set {
        config.milestone_height = milestone_height;
    } else if config.milestone_height == 0 {
        config.milestone_height = default_milestone_height(config.network);
    }
    if max_outbound_set {
        config.max_outbound = max_outbound;
    }
    if max_inbound_set {
        config.max_inbound = max_inbound;
        config.max_inbound_explicit = true;
    }
    config.inhibit_suspend = inhibit_suspend;
    // Map MiB → weight units (1 MiB ≈ 1e6 WU for budget purposes).
    if let Some(mb) = mempool_size_mb {
        config.mempool_max_weight = mb.saturating_mul(1_000_000);
    }
    if !test_activation_heights.is_empty() {
        config
            .test_activation_heights
            .extend(test_activation_heights);
    }
    if let Some(b) = persist_mempool {
        config.persist_mempool = b;
    }
    if !whitelist.is_empty() {
        config.whitelist.extend(whitelist);
    }
    if let Some(b) = blocksonly {
        config.blocksonly = b;
    }
    if let Some(s) = min_relay_fee_btc {
        config.min_relay_fee_btc = Some(s);
    }
    if let Some(h) = mempool_expiry_hours {
        config.mempool_expiry_hours = Some(h);
    }
    if let Some(s) = startup_notify {
        config.startup_notify = Some(s);
    }
    if let Some(s) = alert_notify {
        config.alert_notify = Some(s);
    }
    if let Some(b) = permit_bare_multisig {
        config.permit_bare_multisig = b;
    }
    if let Some(n) = limit_cluster_count {
        config.limit_cluster_count = Some(n);
    }
    if let Some(n) = limit_cluster_size_kvb {
        config.limit_cluster_size_kvb = Some(n);
    }
    if let Some(n) = peer_timeout_secs {
        config.peer_timeout_secs = Some(n);
    }
    if let Some(w) = minimum_chain_work {
        config.minimum_chain_work = Some(w);
    }
    if let Some(t) = mock_time {
        config.mock_time = Some(t);
    }
    if let Some(n) = max_tip_age_secs {
        config.max_tip_age_secs = Some(n);
    }
    if let Some(v) = block_version {
        config.block_version = Some(v);
    }
    if let Some(s) = block_min_tx_fee_btc {
        config.block_min_tx_fee_btc = Some(s);
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
    if max_run_secs.is_some() {
        config.max_run_secs = max_run_secs;
    }

    if let Err(e) = config.ensure_datadir() {
        error!("{e}");
        return ExitCode::FAILURE;
    }

    if smoke {
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
        let rt = match tokio::runtime::Runtime::new() {
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
