//! Client-side Electrum / Esplora benchmark.
//!
//! Suites follow public methodologies:
//! - **casa**: Lopp/Casa 2020–2022 — sequential `get_balance` / `get_history` /
//!   `listunspent` per scripthash; discard warmup; median of remaining passes.
//! - **sparrow**: Sparrow Wallet 2022 — batched `subscribe` (wallet load) then
//!   batched `get_history` (refresh); optional `transaction.get`.
//! - **hot**: fat-history keys (e.g. well-known high-fanout scripts).
//! - **clients**: many concurrent small wallets (`--clients N`) sliced from
//!   the corpus; each connection reloads subscribe/history/utxo. One OS thread
//!   (current-thread runtime) so the runner stays light next to a node.
//!
//! Default `--corpus` matches `--suite` (`clients` defaults to `sparrow`).
//! Packed lists live in `corpora/`: `hot` is public fat keys; `casa`/`sparrow`
//! are unique output scripts from heights spaced genesis→tip (so height-list
//! servers cannot cache one window).
//!
//! Not a product binary. Build: `cargo run -p rbitcoin-bench --features cli --release`.

mod electrum;
mod esplora;
mod jsonrpc;
mod out;
mod progress;
mod stats;
mod suite;
mod targets;
mod wallets;

use crate::electrum::ElectrumClient;
use crate::esplora::EsploraClient;
use crate::out::{write_clients_csv, write_csv};
use crate::progress::Progress;
use crate::stats::format_report;
use crate::suite::{
    electrum_casa, electrum_clients, electrum_hot, electrum_sparrow, esplora_casa, esplora_clients,
    CasaOpts, ClientsOpts, RunOutcome, Suite,
};
use crate::targets::{load_corpus, load_targets};
use crate::wallets::pack_wallets;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub fn cli_main(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    match run(args.into_iter().collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn usage() -> String {
    format!(
        "rbitcoin-bench {} — Electrum/Esplora client benchmark (not built by default)\n\
         \n\
         Usage:\n\
           cargo run -p rbitcoin-bench --features cli --release -- [OPTIONS]\n\
         \n\
         Required:\n\
           --electrum HOST:PORT   Electrum TCP (e.g. 127.0.0.1:50001)\n\
           --esplora http://HOST:PORT\n\
         \n\
         Targets (default: embedded corpus matching --suite):\n\
           --corpus casa|sparrow|hot  packed-in keys (see corpora/)\n\
           --targets FILE             scripthash hex (64) or addresses, one per line\n\
         \n\
         Options:\n\
           --suite casa|sparrow|hot|clients\n\
                                      default casa (casa=Lopp/Casa; sparrow=wallet\n\
                                      load/refresh; hot=fat get_history/listunspent;\n\
                                      clients=N concurrent small-wallet loads)\n\
           --clients N                concurrent connections (clients suite, default 8)\n\
           --wallet-keys N            keys per wallet (default mix 8/16/32)\n\
           --max-txs N                drop keys/wallets over this (default 1000)\n\
           --max-utxos N              drop keys/wallets over this (default 100)\n\
           --warmup N                 discarded first passes (casa/clients, default 1)\n\
           --passes N                 counted passes after warmup (default 9)\n\
           --batch N                  sparrow/clients RPC page size (default 50)\n\
           --fetch-txs                sparrow: also blockchain.transaction.get\n\
           --timeout-secs N           per request (default 30)\n\
           --out FILE                 CSV: casa/hot per-key; clients per-connection\n\
           -h, --help\n\
           -V, --version\n\
         \n\
         Casa: sequential balance/history/utxo; throw away warmup; median of passes.\n\
         Sparrow: subscribe all (load) then get_history all (refresh), batch 50.\n\
         Clients: N TCP/HTTP sessions on one OS thread; each reloads a small wallet\n\
         sliced from sparrow/casa (skip keys that exceed --max-txs/--max-utxos).\n\
         Embedded casa/sparrow keys are spread genesis→tip (not one 200-block window).\n\
         Compare the same corpus against rbitcoin, Fulcrum, electrs, ElectrumX.\n\
         Progress on stderr (~5% and ≥15s); the p50/p95 table stays on stdout.",
        env!("CARGO_PKG_VERSION")
    )
}

#[derive(Debug)]
struct Cfg {
    targets: Option<PathBuf>,
    corpus: Option<String>,
    electrum: Option<String>,
    esplora: Option<String>,
    suite: Suite,
    warmup: u32,
    passes: u32,
    batch: usize,
    fetch_txs: bool,
    timeout: Duration,
    out: Option<PathBuf>,
    clients: usize,
    clients_flag: bool,
    wallet_keys: Option<usize>,
    max_txs: u64,
    max_utxos: u64,
}

impl Default for Cfg {
    fn default() -> Self {
        Self {
            targets: None,
            corpus: None,
            electrum: None,
            esplora: None,
            suite: Suite::Casa,
            warmup: 1,
            passes: 9,
            batch: 50,
            fetch_txs: false,
            timeout: Duration::from_secs(30),
            out: None,
            clients: 8,
            clients_flag: false,
            wallet_keys: None,
            max_txs: 1000,
            max_utxos: 100,
        }
    }
}

fn take(args: &[OsString], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .map(|s| s.to_string_lossy().into_owned())
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_args(args: &[OsString]) -> Result<Cfg, String> {
    let mut cfg = Cfg::default();
    let mut i = 1usize;
    while i < args.len() {
        let a = args[i].to_string_lossy();
        match a.as_ref() {
            "--help" | "-h" => return Err(usage()),
            "--version" | "-V" => {
                return Err(format!("rbitcoin-bench {}", env!("CARGO_PKG_VERSION")));
            }
            "--targets" => cfg.targets = Some(PathBuf::from(take(args, &mut i, "--targets")?)),
            "--corpus" => cfg.corpus = Some(take(args, &mut i, "--corpus")?),
            "--electrum" => cfg.electrum = Some(take(args, &mut i, "--electrum")?),
            "--esplora" => cfg.esplora = Some(take(args, &mut i, "--esplora")?),
            "--suite" => cfg.suite = Suite::parse(&take(args, &mut i, "--suite")?)?,
            "--warmup" => {
                cfg.warmup = take(args, &mut i, "--warmup")?
                    .parse()
                    .map_err(|_| "bad --warmup".to_string())?;
            }
            "--passes" => {
                cfg.passes = take(args, &mut i, "--passes")?
                    .parse()
                    .map_err(|_| "bad --passes".to_string())?;
            }
            "--batch" => {
                cfg.batch = take(args, &mut i, "--batch")?
                    .parse()
                    .map_err(|_| "bad --batch".to_string())?;
            }
            "--timeout-secs" => {
                let n: u64 = take(args, &mut i, "--timeout-secs")?
                    .parse()
                    .map_err(|_| "bad --timeout-secs".to_string())?;
                cfg.timeout = Duration::from_secs(n.max(1));
            }
            "--fetch-txs" => cfg.fetch_txs = true,
            "--out" => cfg.out = Some(PathBuf::from(take(args, &mut i, "--out")?)),
            "--clients" => {
                cfg.clients_flag = true;
                cfg.clients = take(args, &mut i, "--clients")?
                    .parse()
                    .map_err(|_| "bad --clients".to_string())?;
            }
            "--wallet-keys" => {
                cfg.wallet_keys = Some(
                    take(args, &mut i, "--wallet-keys")?
                        .parse()
                        .map_err(|_| "bad --wallet-keys".to_string())?,
                );
            }
            "--max-txs" => {
                cfg.max_txs = take(args, &mut i, "--max-txs")?
                    .parse()
                    .map_err(|_| "bad --max-txs".to_string())?;
            }
            "--max-utxos" => {
                cfg.max_utxos = take(args, &mut i, "--max-utxos")?
                    .parse()
                    .map_err(|_| "bad --max-utxos".to_string())?;
            }
            other => return Err(format!("unknown argument {other}")),
        }
        i += 1;
    }
    Ok(cfg)
}

fn run(args: Vec<OsString>) -> Result<(), String> {
    let cfg = match parse_args(&args) {
        Ok(c) => c,
        Err(msg) if msg.starts_with("rbitcoin-bench ") || msg.starts_with("Usage:") => {
            println!("{msg}");
            return Ok(());
        }
        Err(e) if e.contains("unknown suite") || e.starts_with("unknown argument") => {
            return Err(e);
        }
        Err(e) if e.contains("requires a value") || e.starts_with("bad --") => return Err(e),
        Err(msg) => {
            println!("{msg}");
            return Ok(());
        }
    };
    if args.iter().any(|a| {
        let s = a.to_string_lossy();
        s == "--help" || s == "-h" || s == "--version" || s == "-V"
    }) {
        return Ok(());
    }
    if cfg.out.is_some() && cfg.suite == Suite::Sparrow {
        return Err("--out is casa/hot/clients only".into());
    }
    if cfg.suite != Suite::Clients && (cfg.clients_flag || cfg.wallet_keys.is_some()) {
        return Err("--clients and --wallet-keys require --suite clients".into());
    }
    if cfg.suite == Suite::Clients && cfg.fetch_txs {
        return Err("--fetch-txs is sparrow-only".into());
    }
    let targets = match (&cfg.targets, &cfg.corpus) {
        (Some(path), _) => load_targets(path)?,
        (None, Some(name)) => load_corpus(name)?,
        (None, None) => {
            let name = match cfg.suite {
                Suite::Casa => "casa",
                Suite::Sparrow => "sparrow",
                Suite::Hot => "hot",
                Suite::Clients => "sparrow",
            };
            load_corpus(name)?
        }
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(run_async(cfg, targets))
}

fn casa_units(n_keys: usize, warmup: u32, passes: u32) -> u64 {
    let n_pass = warmup.saturating_add(passes.max(1)) as u64;
    (n_keys as u64).saturating_mul(n_pass)
}

fn sparrow_units(n_keys: usize, batch: usize) -> u64 {
    let batch = batch.max(1);
    let n_batches = n_keys.div_ceil(batch) as u64;
    n_batches.saturating_mul(2)
}

fn clients_units(n_clients: usize, warmup: u32, passes: u32) -> u64 {
    (n_clients as u64).saturating_mul(warmup.saturating_add(passes.max(1)) as u64)
}

fn clients_opts(cfg: &Cfg) -> ClientsOpts {
    ClientsOpts {
        warmup: cfg.warmup,
        passes: cfg.passes,
        batch: cfg.batch,
        max_txs: cfg.max_txs,
        max_utxos: cfg.max_utxos,
    }
}

async fn run_clients(
    cfg: &Cfg,
    targets: &[String],
    backend: &str,
    electrum: Option<&str>,
    esplora: Option<&str>,
) -> Result<RunOutcome, String> {
    let wallets = pack_wallets(targets, cfg.clients, cfg.wallet_keys)?;
    let progress = Arc::new(Mutex::new(Progress::start(
        format!("clients {backend}"),
        clients_units(wallets.len(), cfg.warmup, cfg.passes),
    )));
    let opts = clients_opts(cfg);
    match (electrum, esplora) {
        (Some(addr), None) => electrum_clients(addr, cfg.timeout, wallets, &opts, progress).await,
        (None, Some(url)) => esplora_clients(url, cfg.timeout, wallets, &opts, progress).await,
        _ => Err("use one of --electrum or --esplora".into()),
    }
}

async fn run_async(cfg: Cfg, targets: Vec<String>) -> Result<(), String> {
    let outcome: RunOutcome;
    let backend;
    match (&cfg.electrum, &cfg.esplora) {
        (Some(addr), None) => {
            backend = "electrum";
            outcome = if cfg.suite == Suite::Clients {
                run_clients(&cfg, &targets, backend, Some(addr), None).await?
            } else {
                let mut c = ElectrumClient::connect(addr, cfg.timeout).await?;
                match cfg.suite {
                    Suite::Casa => {
                        let mut progress = Progress::start(
                            format!("casa {backend}"),
                            casa_units(targets.len(), cfg.warmup, cfg.passes),
                        );
                        electrum_casa(
                            &mut c,
                            &targets,
                            &CasaOpts {
                                warmup: cfg.warmup,
                                passes: cfg.passes,
                            },
                            &mut progress,
                        )
                        .await?
                    }
                    Suite::Sparrow => {
                        let mut progress = Progress::start(
                            "sparrow load",
                            sparrow_units(targets.len(), cfg.batch),
                        );
                        electrum_sparrow(&mut c, &targets, cfg.batch, cfg.fetch_txs, &mut progress)
                            .await?
                    }
                    Suite::Hot => {
                        let mut progress =
                            Progress::start(format!("hot {backend}"), targets.len() as u64);
                        electrum_hot(&mut c, &targets, cfg.timeout, &mut progress).await?
                    }
                    Suite::Clients => unreachable!(),
                }
            };
        }
        (None, Some(url)) => {
            backend = "esplora";
            if cfg.suite == Suite::Sparrow {
                return Err("sparrow suite is Electrum-only (subscribe)".into());
            }
            outcome = if cfg.suite == Suite::Clients {
                run_clients(&cfg, &targets, backend, None, Some(url)).await?
            } else {
                let mut c = EsploraClient::connect(url, cfg.timeout).await?;
                match cfg.suite {
                    Suite::Casa | Suite::Hot => {
                        let (warmup, passes, label) = if cfg.suite == Suite::Hot {
                            (0, 1, format!("hot {backend}"))
                        } else {
                            (cfg.warmup, cfg.passes, format!("casa {backend}"))
                        };
                        let mut progress =
                            Progress::start(label, casa_units(targets.len(), warmup, passes));
                        esplora_casa(
                            &mut c,
                            &targets,
                            &CasaOpts { warmup, passes },
                            &mut progress,
                        )
                        .await?
                    }
                    Suite::Sparrow => unreachable!(),
                    Suite::Clients => unreachable!(),
                }
            };
        }
        (Some(_), Some(_)) => return Err("use one of --electrum or --esplora".into()),
        (None, None) => {
            return Err("need --electrum HOST:PORT or --esplora http://HOST:PORT".into())
        }
    }
    let name = match cfg.suite {
        Suite::Casa => "casa",
        Suite::Sparrow => "sparrow",
        Suite::Hot => "hot",
        Suite::Clients => "clients",
    };
    if cfg.suite == Suite::Clients {
        println!(
            "clients={} wallets={} max_txs={} max_utxos={}",
            cfg.clients,
            outcome.clients.len(),
            cfg.max_txs,
            cfg.max_utxos
        );
    }
    println!("{}", format_report(name, backend, &outcome.samples));
    if let Some(path) = &cfg.out {
        let passes = if cfg.suite == Suite::Hot {
            1
        } else {
            cfg.passes.max(1) as usize
        };
        if cfg.suite == Suite::Clients {
            write_clients_csv(path, &outcome.clients, passes)?;
            eprintln!(
                "rbitcoin-bench: wrote {} clients to {}",
                outcome.clients.len(),
                path.display()
            );
        } else {
            write_csv(path, &outcome.keys, passes)?;
            eprintln!(
                "rbitcoin-bench: wrote {} keys to {}",
                outcome.keys.len(),
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_help_and_flags() {
        let args = vec![OsString::from("rbitcoin-bench"), OsString::from("--help")];
        assert!(parse_args(&args).is_err());
        let args = vec![
            OsString::from("rbitcoin-bench"),
            OsString::from("--suite"),
            OsString::from("sparrow"),
            OsString::from("--batch"),
            OsString::from("25"),
            OsString::from("--targets"),
            OsString::from("/tmp/x"),
            OsString::from("--electrum"),
            OsString::from("127.0.0.1:1"),
            OsString::from("--out"),
            OsString::from("/tmp/casa.csv"),
        ];
        let c = parse_args(&args).unwrap();
        assert_eq!(c.batch, 25);
        assert_eq!(c.suite, Suite::Sparrow);
        assert_eq!(c.clients, 8);
        assert_eq!(
            c.out.as_deref().map(|p| p.to_str().unwrap()),
            Some("/tmp/casa.csv")
        );
        let args = vec![
            OsString::from("rbitcoin-bench"),
            OsString::from("--corpus"),
            OsString::from("hot"),
            OsString::from("--electrum"),
            OsString::from("127.0.0.1:1"),
        ];
        let c = parse_args(&args).unwrap();
        assert_eq!(c.corpus.as_deref(), Some("hot"));
        assert!(c.targets.is_none());
    }

    #[test]
    fn parse_unknown() {
        let args = vec![OsString::from("b"), OsString::from("--nope")];
        assert!(parse_args(&args).unwrap_err().contains("unknown"));
    }

    #[test]
    fn sparrow_out_is_rejected() {
        let code = cli_main([
            OsString::from("rbitcoin-bench"),
            OsString::from("--suite"),
            OsString::from("sparrow"),
            OsString::from("--out"),
            OsString::from("/tmp/x.csv"),
            OsString::from("--electrum"),
            OsString::from("127.0.0.1:1"),
        ]);
        assert_eq!(code, ExitCode::from(1));
    }

    #[test]
    fn cli_help_exits_ok() {
        let code = cli_main([OsString::from("rbitcoin-bench"), OsString::from("-h")]);
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn work_units_cover_passes_and_batches() {
        assert_eq!(casa_units(10, 1, 9), 100);
        assert_eq!(sparrow_units(100, 50), 4);
        assert_eq!(sparrow_units(0, 50), 0);
        assert_eq!(clients_units(8, 1, 9), 80);
    }

    #[test]
    fn parse_clients_flags() {
        let args = vec![
            OsString::from("rbitcoin-bench"),
            OsString::from("--suite"),
            OsString::from("clients"),
            OsString::from("--clients"),
            OsString::from("32"),
            OsString::from("--wallet-keys"),
            OsString::from("16"),
            OsString::from("--max-txs"),
            OsString::from("500"),
            OsString::from("--max-utxos"),
            OsString::from("40"),
            OsString::from("--electrum"),
            OsString::from("127.0.0.1:1"),
        ];
        let c = parse_args(&args).unwrap();
        assert_eq!(c.suite, Suite::Clients);
        assert_eq!(c.clients, 32);
        assert_eq!(c.wallet_keys, Some(16));
        assert_eq!(c.max_txs, 500);
        assert_eq!(c.max_utxos, 40);
        assert!(c.clients_flag);
    }

    #[test]
    fn clients_flags_rejected_on_casa() {
        let code = cli_main([
            OsString::from("rbitcoin-bench"),
            OsString::from("--suite"),
            OsString::from("casa"),
            OsString::from("--clients"),
            OsString::from("4"),
            OsString::from("--electrum"),
            OsString::from("127.0.0.1:1"),
        ]);
        assert_eq!(code, ExitCode::from(1));
    }

    #[test]
    fn clients_cli_two_connections() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(false).unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let _h = std::thread::spawn(move || {
            for _ in 0..8 {
                let Ok((stream, _)) = listener.accept() else {
                    break;
                };
                std::thread::spawn(move || {
                    let mut r = BufReader::new(stream.try_clone().unwrap());
                    let mut w = stream;
                    let mut line = String::new();
                    loop {
                        line.clear();
                        if r.read_line(&mut line).unwrap_or(0) == 0 {
                            break;
                        }
                        let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
                        let method = v["method"].as_str().unwrap_or("");
                        let result = match method {
                            "server.version" => serde_json::json!(["ok", "1.4"]),
                            "blockchain.scripthash.subscribe" => serde_json::json!("s"),
                            "blockchain.scripthash.get_history" => {
                                serde_json::json!([{"height":10,"tx_hash":"aa"}])
                            }
                            "blockchain.scripthash.listunspent" => {
                                serde_json::json!([{"tx_hash":"aa","tx_pos":0,"height":10,"value":1}])
                            }
                            _ => serde_json::json!(null),
                        };
                        let resp = serde_json::json!({"id": v["id"], "result": result});
                        let _ = writeln!(w, "{resp}");
                        let _ = w.flush();
                    }
                });
            }
        });
        let dir = std::env::temp_dir().join(format!("rbtc-bench-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = dir.join("t.txt");
        let csv = dir.join("c.csv");
        let mut body = String::new();
        for i in 0..4u32 {
            body.push_str(&format!("{i:064x}\n"));
        }
        std::fs::write(&t, body).unwrap();
        let code = cli_main([
            OsString::from("rbitcoin-bench"),
            OsString::from("--suite"),
            OsString::from("clients"),
            OsString::from("--clients"),
            OsString::from("2"),
            OsString::from("--wallet-keys"),
            OsString::from("2"),
            OsString::from("--warmup"),
            OsString::from("0"),
            OsString::from("--passes"),
            OsString::from("1"),
            OsString::from("--electrum"),
            OsString::from(&addr),
            OsString::from("--targets"),
            OsString::from(t.as_os_str()),
            OsString::from("--out"),
            OsString::from(csv.as_os_str()),
        ]);
        assert_eq!(code, ExitCode::SUCCESS);
        let out = std::fs::read_to_string(&csv).unwrap();
        assert!(out.contains("wallet_load_us_1"), "{out}");
        assert_eq!(out.lines().count(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
