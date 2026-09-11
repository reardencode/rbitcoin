//! Casa sequential medians, Sparrow batched load, concurrent small-wallet clients.

use crate::electrum::ElectrumClient;
use crate::esplora::EsploraClient;
use crate::jsonrpc;
use crate::out::{ClientRow, KeyRow};
use crate::progress::Progress;
use crate::stats::Sample;
use crate::wallets;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

#[derive(Default)]
pub struct RunOutcome {
    pub samples: Vec<Sample>,
    pub keys: Vec<KeyRow>,
    pub clients: Vec<ClientRow>,
}

fn us(nanos: u64) -> u64 {
    nanos / 1000
}

fn fill_key_meta(row: &mut KeyRow, hist: &Value, utxo: &Value, txs: u64, utxos: u64) {
    let (lo, hi) = jsonrpc::height_span(hist);
    row.oldest_tx = lo;
    row.newest_tx = hi;
    let (ulo, uhi) = jsonrpc::height_span(utxo);
    row.oldest_utxo = ulo;
    row.newest_utxo = uhi;
    row.txs = txs;
    row.utxos = utxos;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suite {
    Casa,
    Sparrow,
    Hot,
    Clients,
}

impl Suite {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "casa" => Ok(Self::Casa),
            "sparrow" => Ok(Self::Sparrow),
            "hot" => Ok(Self::Hot),
            "clients" => Ok(Self::Clients),
            other => Err(format!("unknown suite {other} (casa|sparrow|hot|clients)")),
        }
    }
}

pub struct CasaOpts {
    pub warmup: u32,
    pub passes: u32,
}

impl Default for CasaOpts {
    fn default() -> Self {
        Self {
            warmup: 1,
            passes: 9,
        }
    }
}

pub async fn electrum_casa(
    client: &mut ElectrumClient,
    targets: &[String],
    opts: &CasaOpts,
    progress: &mut Progress,
) -> Result<RunOutcome, String> {
    let keep = opts.passes.max(1);
    let total = opts.warmup.saturating_add(keep);
    let mut samples = Vec::new();
    let mut keys = Vec::new();
    for sh in targets {
        let params = json!([sh]);
        let mut row = KeyRow {
            scripthash: sh.clone(),
            ..KeyRow::default()
        };
        for pass in 0..total {
            let (bal, bns) = client
                .call("blockchain.scripthash.get_balance", params.clone())
                .await?;
            let (hist, hns) = client
                .call("blockchain.scripthash.get_history", params.clone())
                .await?;
            let (utxo, uns) = client
                .call("blockchain.scripthash.listunspent", params.clone())
                .await?;
            let history_n = jsonrpc::history_len(&hist);
            let utxo_n = jsonrpc::utxo_len(&utxo);
            let _ = bal;
            if pass >= opts.warmup {
                fill_key_meta(&mut row, &hist, &utxo, history_n, utxo_n);
                row.get_balance_us.push(us(bns));
                row.get_history_us.push(us(hns));
                row.listunspent_us.push(us(uns));
                samples.push(Sample {
                    query: "get_balance",
                    nanos: bns,
                    history_n,
                    utxo_n,
                });
                samples.push(Sample {
                    query: "get_history",
                    nanos: hns,
                    history_n,
                    utxo_n,
                });
                samples.push(Sample {
                    query: "listunspent",
                    nanos: uns,
                    history_n,
                    utxo_n,
                });
            }
            progress.tick();
        }
        keys.push(row);
    }
    progress.finish();
    Ok(RunOutcome {
        samples,
        keys,
        clients: Vec::new(),
    })
}

pub async fn esplora_casa(
    client: &mut EsploraClient,
    targets: &[String],
    opts: &CasaOpts,
    progress: &mut Progress,
) -> Result<RunOutcome, String> {
    let keep = opts.passes.max(1);
    let total = opts.warmup.saturating_add(keep);
    let mut samples = Vec::new();
    let mut keys = Vec::new();
    for sh in targets {
        let mut row = KeyRow {
            scripthash: sh.clone(),
            ..KeyRow::default()
        };
        for pass in 0..total {
            let (info, ins) = client.get_json(&format!("/scripthash/{sh}")).await?;
            let (txs, tns) = client.get_json(&format!("/scripthash/{sh}/txs")).await?;
            let (utxo, uns) = client.get_json(&format!("/scripthash/{sh}/utxo")).await?;
            let history_n = info
                .pointer("/chain_stats/tx_count")
                .and_then(|v| v.as_u64())
                .unwrap_or_else(|| jsonrpc::history_len(&txs));
            let utxo_n = jsonrpc::utxo_len(&utxo);
            if pass >= opts.warmup {
                fill_key_meta(&mut row, &txs, &utxo, history_n, utxo_n);
                row.get_balance_us.push(us(ins));
                row.get_history_us.push(us(tns));
                row.listunspent_us.push(us(uns));
                samples.push(Sample {
                    query: "get_balance",
                    nanos: ins,
                    history_n,
                    utxo_n,
                });
                samples.push(Sample {
                    query: "get_history",
                    nanos: tns,
                    history_n,
                    utxo_n,
                });
                samples.push(Sample {
                    query: "listunspent",
                    nanos: uns,
                    history_n,
                    utxo_n,
                });
            }
            progress.tick();
        }
        keys.push(row);
    }
    progress.finish();
    Ok(RunOutcome {
        samples,
        keys,
        clients: Vec::new(),
    })
}

pub async fn electrum_sparrow(
    client: &mut ElectrumClient,
    targets: &[String],
    batch: usize,
    fetch_txs: bool,
    progress: &mut Progress,
) -> Result<RunOutcome, String> {
    let batch = batch.max(1);
    let mut samples = Vec::new();
    let mut i = 0;
    while i < targets.len() {
        let end = (i + batch).min(targets.len());
        let chunk = &targets[i..end];
        let reqs: Vec<(&str, Value)> = chunk
            .iter()
            .map(|sh| ("blockchain.scripthash.subscribe", json!([sh])))
            .collect();
        let (_vals, ns) = client.call_batch(&reqs).await?;
        samples.push(Sample {
            query: "subscribe_batch",
            nanos: ns,
            history_n: chunk.len() as u64,
            utxo_n: 0,
        });
        progress.tick();
        i = end;
    }
    progress.set_label("sparrow refresh");
    i = 0;
    let mut txids: Vec<String> = Vec::new();
    while i < targets.len() {
        let end = (i + batch).min(targets.len());
        let chunk = &targets[i..end];
        let reqs: Vec<(&str, Value)> = chunk
            .iter()
            .map(|sh| ("blockchain.scripthash.get_history", json!([sh])))
            .collect();
        let (vals, ns) = client.call_batch(&reqs).await?;
        samples.push(Sample {
            query: "get_history_batch",
            nanos: ns,
            history_n: chunk.len() as u64,
            utxo_n: 0,
        });
        progress.tick();
        if fetch_txs {
            for v in &vals {
                if let Some(arr) = v.as_array() {
                    for item in arr {
                        if let Some(h) = item.get("tx_hash").and_then(|x| x.as_str()) {
                            txids.push(h.to_string());
                        }
                    }
                }
            }
        }
        i = end;
    }
    if fetch_txs {
        txids.sort();
        txids.dedup();
        let n_tx_batches = txids.len().div_ceil(batch) as u64;
        progress.add_work(n_tx_batches);
        progress.set_label("sparrow txs");
        i = 0;
        while i < txids.len() {
            let end = (i + batch).min(txids.len());
            let reqs: Vec<(&str, Value)> = txids[i..end]
                .iter()
                .map(|h| ("blockchain.transaction.get", json!([h])))
                .collect();
            let (_vals, ns) = client.call_batch(&reqs).await?;
            samples.push(Sample {
                query: "transaction_get_batch",
                nanos: ns,
                history_n: (end - i) as u64,
                utxo_n: 0,
            });
            progress.tick();
            i = end;
        }
    }
    progress.finish();
    Ok(RunOutcome {
        samples,
        keys: Vec::new(),
        clients: Vec::new(),
    })
}

pub async fn electrum_hot(
    client: &mut ElectrumClient,
    targets: &[String],
    timeout: Duration,
    progress: &mut Progress,
) -> Result<RunOutcome, String> {
    let _ = timeout;
    let mut samples = Vec::new();
    let mut keys = Vec::new();
    for sh in targets {
        let params = json!([sh]);
        let mut row = KeyRow {
            scripthash: sh.clone(),
            ..KeyRow::default()
        };
        let (hist, hns) = client
            .call("blockchain.scripthash.get_history", params.clone())
            .await?;
        let history_n = jsonrpc::history_len(&hist);
        samples.push(Sample {
            query: "get_history",
            nanos: hns,
            history_n,
            utxo_n: 0,
        });
        let (utxo, uns) = client
            .call("blockchain.scripthash.listunspent", params)
            .await?;
        let utxo_n = jsonrpc::utxo_len(&utxo);
        fill_key_meta(&mut row, &hist, &utxo, history_n, utxo_n);
        row.get_history_us.push(us(hns));
        row.listunspent_us.push(us(uns));
        samples.push(Sample {
            query: "listunspent",
            nanos: uns,
            history_n,
            utxo_n,
        });
        keys.push(row);
        progress.tick();
    }
    progress.finish();
    Ok(RunOutcome {
        samples,
        keys,
        clients: Vec::new(),
    })
}

#[derive(Clone, Copy, Debug)]
pub struct ClientsOpts {
    pub warmup: u32,
    pub passes: u32,
    pub batch: usize,
    pub max_txs: u64,
    pub max_utxos: u64,
}

impl Default for ClientsOpts {
    fn default() -> Self {
        Self {
            warmup: 1,
            passes: 9,
            batch: 50,
            max_txs: 1000,
            max_utxos: 100,
        }
    }
}

fn lock_tick(progress: &Arc<Mutex<Progress>>) {
    if let Ok(mut p) = progress.lock() {
        p.tick();
    }
}

fn probe_sum(items: &[(String, u64, u64)], kept: &[String]) -> (u64, u64) {
    let mut txs = 0u64;
    let mut utxos = 0u64;
    for (sh, t, u) in items {
        if kept.iter().any(|k| k == sh) {
            txs = txs.saturating_add(*t);
            utxos = utxos.saturating_add(*u);
        }
    }
    (txs, utxos)
}

async fn electrum_one_wallet(
    addr: String,
    timeout: Duration,
    mut keys: Vec<String>,
    client_id: u32,
    opts: ClientsOpts,
    progress: Arc<Mutex<Progress>>,
) -> Result<(Vec<Sample>, ClientRow), String> {
    let mut client = ElectrumClient::connect(&addr, timeout).await?;
    let keep_passes = opts.passes.max(1);
    let total = opts.warmup.saturating_add(keep_passes);
    let batch = opts.batch.max(1);
    let mut samples = Vec::new();
    let mut load_us = Vec::new();
    let mut last_txs = 0u64;
    let mut last_utxos = 0u64;
    let mut last_n_keys = keys.len();
    for pass in 0..total {
        if keys.is_empty() {
            lock_tick(&progress);
            continue;
        }
        let t0 = Instant::now();
        let mut probed: Vec<(String, u64, u64)> = Vec::with_capacity(keys.len());
        let mut i = 0usize;
        while i < keys.len() {
            let end = (i + batch).min(keys.len());
            let chunk = &keys[i..end];
            let subs: Vec<(&str, Value)> = chunk
                .iter()
                .map(|sh| ("blockchain.scripthash.subscribe", json!([sh])))
                .collect();
            let (_svals, sns) = client.call_batch(&subs).await?;
            let hreqs: Vec<(&str, Value)> = chunk
                .iter()
                .map(|sh| ("blockchain.scripthash.get_history", json!([sh])))
                .collect();
            let (hvals, hns) = client.call_batch(&hreqs).await?;
            let ureqs: Vec<(&str, Value)> = chunk
                .iter()
                .map(|sh| ("blockchain.scripthash.listunspent", json!([sh])))
                .collect();
            let (uvals, uns) = client.call_batch(&ureqs).await?;
            let mut hist_sum = 0u64;
            let mut utxo_sum = 0u64;
            for (j, sh) in chunk.iter().enumerate() {
                let hn = jsonrpc::history_len(hvals.get(j).unwrap_or(&Value::Null));
                let un = jsonrpc::utxo_len(uvals.get(j).unwrap_or(&Value::Null));
                probed.push((sh.clone(), hn, un));
                hist_sum = hist_sum.saturating_add(hn);
                utxo_sum = utxo_sum.saturating_add(un);
            }
            if pass >= opts.warmup {
                samples.push(Sample {
                    query: "subscribe_batch",
                    nanos: sns,
                    history_n: chunk.len() as u64,
                    utxo_n: 0,
                });
                samples.push(Sample {
                    query: "get_history_batch",
                    nanos: hns,
                    history_n: hist_sum,
                    utxo_n: 0,
                });
                samples.push(Sample {
                    query: "listunspent_batch",
                    nanos: uns,
                    history_n: hist_sum,
                    utxo_n: utxo_sum,
                });
            }
            i = end;
        }
        let kept = wallets::keep_small(&probed, opts.max_txs, opts.max_utxos);
        let (txs, utxos) = probe_sum(&probed, &kept);
        last_txs = txs;
        last_utxos = utxos;
        last_n_keys = kept.len();
        let wall = u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
        if pass >= opts.warmup && !kept.is_empty() {
            samples.push(Sample {
                query: "wallet_load",
                nanos: wall,
                history_n: txs,
                utxo_n: utxos,
            });
            load_us.push(us(wall));
        }
        keys = kept;
        lock_tick(&progress);
    }
    Ok((
        samples,
        ClientRow {
            client: client_id,
            n_keys: last_n_keys,
            txs: last_txs,
            utxos: last_utxos,
            wallet_load_us: load_us,
        },
    ))
}

async fn esplora_one_wallet(
    url: String,
    timeout: Duration,
    mut keys: Vec<String>,
    client_id: u32,
    opts: ClientsOpts,
    progress: Arc<Mutex<Progress>>,
) -> Result<(Vec<Sample>, ClientRow), String> {
    let mut client = EsploraClient::connect(&url, timeout).await?;
    let keep_passes = opts.passes.max(1);
    let total = opts.warmup.saturating_add(keep_passes);
    let mut samples = Vec::new();
    let mut load_us = Vec::new();
    let mut last_txs = 0u64;
    let mut last_utxos = 0u64;
    let mut last_n_keys = keys.len();
    for pass in 0..total {
        if keys.is_empty() {
            lock_tick(&progress);
            continue;
        }
        let t0 = Instant::now();
        let mut probed: Vec<(String, u64, u64)> = Vec::with_capacity(keys.len());
        for sh in &keys {
            let (info, ins) = client.get_json(&format!("/scripthash/{sh}")).await?;
            let (txs_v, tns) = client.get_json(&format!("/scripthash/{sh}/txs")).await?;
            let (utxo, uns) = client.get_json(&format!("/scripthash/{sh}/utxo")).await?;
            let hn = info
                .pointer("/chain_stats/tx_count")
                .and_then(|v| v.as_u64())
                .unwrap_or_else(|| jsonrpc::history_len(&txs_v));
            let un = jsonrpc::utxo_len(&utxo);
            probed.push((sh.clone(), hn, un));
            if pass >= opts.warmup {
                samples.push(Sample {
                    query: "get_balance",
                    nanos: ins,
                    history_n: hn,
                    utxo_n: un,
                });
                samples.push(Sample {
                    query: "get_history",
                    nanos: tns,
                    history_n: hn,
                    utxo_n: un,
                });
                samples.push(Sample {
                    query: "listunspent",
                    nanos: uns,
                    history_n: hn,
                    utxo_n: un,
                });
            }
        }
        let kept = wallets::keep_small(&probed, opts.max_txs, opts.max_utxos);
        let (txs, utxos) = probe_sum(&probed, &kept);
        last_txs = txs;
        last_utxos = utxos;
        last_n_keys = kept.len();
        let wall = u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
        if pass >= opts.warmup && !kept.is_empty() {
            samples.push(Sample {
                query: "wallet_load",
                nanos: wall,
                history_n: txs,
                utxo_n: utxos,
            });
            load_us.push(us(wall));
        }
        keys = kept;
        lock_tick(&progress);
    }
    Ok((
        samples,
        ClientRow {
            client: client_id,
            n_keys: last_n_keys,
            txs: last_txs,
            utxos: last_utxos,
            wallet_load_us: load_us,
        },
    ))
}

async fn join_client_set(
    mut set: JoinSet<Result<(Vec<Sample>, ClientRow), String>>,
    progress: &Arc<Mutex<Progress>>,
) -> Result<RunOutcome, String> {
    let mut samples = Vec::new();
    let mut clients = Vec::new();
    let mut first_err = None;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok((s, row))) => {
                samples.extend(s);
                clients.push(row);
            }
            Ok(Err(e)) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e.to_string());
                }
            }
        }
    }
    if let Ok(mut p) = progress.lock() {
        p.finish();
    }
    if let Some(e) = first_err {
        return Err(e);
    }
    clients.sort_by_key(|c| c.client);
    Ok(RunOutcome {
        samples,
        keys: Vec::new(),
        clients,
    })
}

pub async fn electrum_clients(
    addr: &str,
    timeout: Duration,
    wallets: Vec<Vec<String>>,
    opts: &ClientsOpts,
    progress: Arc<Mutex<Progress>>,
) -> Result<RunOutcome, String> {
    if wallets.is_empty() {
        if let Ok(mut p) = progress.lock() {
            p.finish();
        }
        return Ok(RunOutcome::default());
    }
    let mut set = JoinSet::new();
    let opts = *opts;
    for (i, wallet) in wallets.into_iter().enumerate() {
        let addr = addr.to_string();
        let progress = Arc::clone(&progress);
        set.spawn(async move {
            electrum_one_wallet(addr, timeout, wallet, i as u32, opts, progress).await
        });
    }
    join_client_set(set, &progress).await
}

pub async fn esplora_clients(
    url: &str,
    timeout: Duration,
    wallets: Vec<Vec<String>>,
    opts: &ClientsOpts,
    progress: Arc<Mutex<Progress>>,
) -> Result<RunOutcome, String> {
    if wallets.is_empty() {
        if let Ok(mut p) = progress.lock() {
            p.finish();
        }
        return Ok(RunOutcome::default());
    }
    let mut set = JoinSet::new();
    let opts = *opts;
    for (i, wallet) in wallets.into_iter().enumerate() {
        let url = url.to_string();
        let progress = Arc::clone(&progress);
        set.spawn(async move {
            esplora_one_wallet(url, timeout, wallet, i as u32, opts, progress).await
        });
    }
    join_client_set(set, &progress).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_parse() {
        assert_eq!(Suite::parse("casa").unwrap(), Suite::Casa);
        assert_eq!(Suite::parse("clients").unwrap(), Suite::Clients);
        assert!(Suite::parse("lopp").is_err());
    }

    #[tokio::test]
    async fn electrum_casa_drops_warmup() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let (r, mut w) = s.into_split();
            let mut br = BufReader::new(r);
            loop {
                let mut line = String::new();
                if br.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                let v: Value = serde_json::from_str(line.trim()).unwrap();
                let id = v["id"].clone();
                let method = v["method"].as_str().unwrap_or("");
                let result = match method {
                    "server.version" => json!(["ok", "1.4"]),
                    "blockchain.scripthash.get_balance" => {
                        json!({"confirmed": 1, "unconfirmed": 0})
                    }
                    "blockchain.scripthash.get_history" => {
                        json!([{"height":10,"tx_hash":"aa"},{"height":800000,"tx_hash":"bb"}])
                    }
                    "blockchain.scripthash.listunspent" => {
                        json!([{"tx_hash":"bb","tx_pos":0,"height":800000,"value":1}])
                    }
                    _ => json!(null),
                };
                let resp = json!({"id": id, "result": result});
                w.write_all(resp.to_string().as_bytes()).await.unwrap();
                w.write_all(b"\n").await.unwrap();
            }
        });
        let mut c = ElectrumClient::connect(&addr, Duration::from_secs(2))
            .await
            .unwrap();
        let sh = "ab".repeat(32);
        let mut progress = Progress::start("casa test", 3);
        let out = electrum_casa(
            &mut c,
            std::slice::from_ref(&sh),
            &CasaOpts {
                warmup: 1,
                passes: 2,
            },
            &mut progress,
        )
        .await
        .unwrap();
        assert_eq!(out.samples.len(), 6);
        assert_eq!(out.samples[0].query, "get_balance");
        assert_eq!(out.samples[0].history_n, 2);
        assert_eq!(out.keys.len(), 1);
        let k = &out.keys[0];
        assert_eq!(k.scripthash, sh);
        assert_eq!(k.oldest_tx, Some(10));
        assert_eq!(k.newest_tx, Some(800_000));
        assert_eq!(k.oldest_utxo, Some(800_000));
        assert_eq!(k.newest_utxo, Some(800_000));
        assert_eq!(k.txs, 2);
        assert_eq!(k.utxos, 1);
        assert_eq!(k.get_balance_us.len(), 2);
        assert_eq!(k.get_history_us.len(), 2);
        assert_eq!(k.listunspent_us.len(), 2);
    }

    #[tokio::test]
    async fn electrum_sparrow_batches() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let (r, mut w) = s.into_split();
            let mut br = BufReader::new(r);
            loop {
                let mut line = String::new();
                if br.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                let v: Value = serde_json::from_str(line.trim()).unwrap();
                let resp = json!({"id": v["id"], "result": []});
                w.write_all(resp.to_string().as_bytes()).await.unwrap();
                w.write_all(b"\n").await.unwrap();
            }
        });
        let mut c = ElectrumClient::connect(&addr, Duration::from_secs(2))
            .await
            .unwrap();
        let a = "ab".repeat(32);
        let b = "cd".repeat(32);
        let mut progress = Progress::start("sparrow test", 2);
        let out = electrum_sparrow(&mut c, &[a, b], 2, false, &mut progress)
            .await
            .unwrap();
        assert!(out.samples.iter().any(|s| s.query == "subscribe_batch"));
        assert!(out.samples.iter().any(|s| s.query == "get_history_batch"));
        assert!(out.keys.is_empty());
    }

    async fn handle_electrum_conn(s: tokio::net::TcpStream) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let (r, mut w) = s.into_split();
        let mut br = BufReader::new(r);
        loop {
            let mut line = String::new();
            if br.read_line(&mut line).await.unwrap() == 0 {
                break;
            }
            let v: Value = serde_json::from_str(line.trim()).unwrap();
            let method = v["method"].as_str().unwrap_or("");
            let sh = v["params"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|x| x.as_str())
                .unwrap_or("");
            let result = match method {
                "server.version" => json!(["ok", "1.4"]),
                "blockchain.scripthash.subscribe" => json!("s"),
                "blockchain.scripthash.get_history" => {
                    if sh.starts_with("ff") {
                        let items: Vec<Value> = (0..1001)
                            .map(|i| json!({"height": i + 1, "tx_hash": "aa"}))
                            .collect();
                        json!(items)
                    } else {
                        json!([{"height": 10, "tx_hash": "aa"}])
                    }
                }
                "blockchain.scripthash.listunspent" => {
                    json!([{"tx_hash":"aa","tx_pos":0,"height":10,"value":1}])
                }
                _ => json!(null),
            };
            let resp = json!({"id": v["id"], "result": result});
            w.write_all(resp.to_string().as_bytes()).await.unwrap();
            w.write_all(b"\n").await.unwrap();
        }
    }

    async fn spawn_electrum_many(peak: Arc<std::sync::atomic::AtomicUsize>) -> String {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::net::TcpListener;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let live = Arc::new(AtomicUsize::new(0));
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else {
                    break;
                };
                let cur = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(cur, Ordering::SeqCst);
                let live = Arc::clone(&live);
                tokio::spawn(async move {
                    handle_electrum_conn(s).await;
                    live.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn electrum_clients_two_connections_record_wallet_load() {
        use std::sync::atomic::AtomicUsize;
        let peak = Arc::new(AtomicUsize::new(0));
        let addr = spawn_electrum_many(Arc::clone(&peak)).await;
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let c = "cc".repeat(32);
        let d = "dd".repeat(32);
        let progress = Arc::new(Mutex::new(Progress::start("clients test", 4)));
        let out = electrum_clients(
            &addr,
            Duration::from_secs(2),
            vec![vec![a, b], vec![c, d]],
            &ClientsOpts {
                warmup: 0,
                passes: 2,
                batch: 50,
                max_txs: 1000,
                max_utxos: 100,
            },
            progress,
        )
        .await
        .unwrap();
        let loads: Vec<_> = out
            .samples
            .iter()
            .filter(|s| s.query == "wallet_load")
            .collect();
        assert_eq!(loads.len(), 4);
        assert_eq!(out.clients.len(), 2);
        assert!(out.clients.iter().all(|r| r.n_keys == 2));
        assert!(out.clients.iter().all(|r| r.wallet_load_us.len() == 2));
        assert!(
            peak.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "peak={}",
            peak.load(std::sync::atomic::Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn electrum_clients_drops_fat_key() {
        use std::sync::atomic::AtomicUsize;
        let peak = Arc::new(AtomicUsize::new(0));
        let addr = spawn_electrum_many(Arc::clone(&peak)).await;
        let small = "aa".repeat(32);
        let fat = "ff".repeat(32);
        let progress = Arc::new(Mutex::new(Progress::start("fat test", 2)));
        let out = electrum_clients(
            &addr,
            Duration::from_secs(2),
            vec![vec![small, fat]],
            &ClientsOpts {
                warmup: 0,
                passes: 2,
                batch: 50,
                max_txs: 1000,
                max_utxos: 100,
            },
            progress,
        )
        .await
        .unwrap();
        assert_eq!(out.clients.len(), 1);
        assert_eq!(out.clients[0].n_keys, 1);
        assert_eq!(out.clients[0].txs, 1);
        let loads: Vec<_> = out
            .samples
            .iter()
            .filter(|s| s.query == "wallet_load")
            .collect();
        assert_eq!(loads.len(), 2);
        assert!(loads.iter().all(|s| s.history_n == 1));
    }

    async fn spawn_esplora_many() -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    loop {
                        let mut tmp = [0u8; 512];
                        let n = match s.read(&mut tmp).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&tmp[..n]);
                        while let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = buf[..pos].to_vec();
                            buf.drain(..pos + 4);
                            let path = String::from_utf8_lossy(&head);
                            let fat = path.contains("/scripthash/ff");
                            let body = if path.contains("/utxo") {
                                b"[{\"txid\":\"aa\",\"status\":{\"block_height\":10}}]".to_vec()
                            } else if path.contains("/txs") {
                                if fat {
                                    let items: Vec<String> = (0..1001)
                                        .map(|i| {
                                            format!(
                                                "{{\"txid\":\"aa\",\"status\":{{\"block_height\":{}}}}}",
                                                i + 1
                                            )
                                        })
                                        .collect();
                                    format!("[{}]", items.join(",")).into_bytes()
                                } else {
                                    b"[{\"txid\":\"aa\",\"status\":{\"block_height\":10}}]".to_vec()
                                }
                            } else {
                                let n = if fat { 1001 } else { 1 };
                                format!("{{\"chain_stats\":{{\"tx_count\":{n}}}}}").into_bytes()
                            };
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                                body.len()
                            );
                            if s.write_all(resp.as_bytes()).await.is_err() {
                                return;
                            }
                            if s.write_all(&body).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
        format!("http://127.0.0.1:{}", addr.port())
    }

    #[tokio::test]
    async fn esplora_clients_wallet_load() {
        let url = spawn_esplora_many().await;
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let progress = Arc::new(Mutex::new(Progress::start("esplora clients", 2)));
        let out = esplora_clients(
            &url,
            Duration::from_secs(2),
            vec![vec![a], vec![b]],
            &ClientsOpts {
                warmup: 0,
                passes: 1,
                batch: 50,
                max_txs: 1000,
                max_utxos: 100,
            },
            progress,
        )
        .await
        .unwrap();
        assert_eq!(
            out.samples
                .iter()
                .filter(|s| s.query == "wallet_load")
                .count(),
            2
        );
        assert_eq!(out.clients.len(), 2);
    }
}
