//! End of IBD: tip follow, scripthash history, and restart on a live miner.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, BlockHash, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    Work,
};
use rbitcoin_consensus::{next_work_bits, ChainParams, Milestone};
use rbitcoin_electrum::electrum_scripthash_hex;
use rbitcoin_ibd::IbdConfig;
use rbitcoin_net::{NetAddr, P2PNode};
use rbitcoin_node::{run_p2p, NodeConfig};
use rbitcoin_primitives::{Fk, Height, Network};
use rbitcoin_query::Query;
use rbitcoin_store::{script_hash, ScriptHashRecord};
use rbitcoin_test::mine::{
    coinbase_tx, mine_regtest_block, mine_regtest_block_at, regtest_genesis,
};
use rbitcoin_test::TestDatadir;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

fn llvm_cov_wall(default_secs: u64, llvm_secs: u64) -> Duration {
    if std::env::var_os("CARGO_LLVM_COV").is_some() {
        Duration::from_secs(llvm_secs)
    } else {
        Duration::from_secs(default_secs)
    }
}

fn any_port() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn spend_to(prev: Txid, value: Amount, script: Vec<u8>) -> Transaction {
    Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey: ScriptBuf::from_bytes(script),
        }],
    }
}

/// Coinbases pay script A (`0x51`). One mature spend pays script B (`0x52`).
fn fixture_chain() -> (Vec<bitcoin::Block>, BTreeSet<String>, BTreeSet<String>) {
    let maturity = ChainParams::regtest().coinbase_maturity();
    let genesis = regtest_genesis();
    let mut blocks = vec![genesis.clone()];
    let mut tip = genesis.block_hash();
    let mut time = genesis.header.time;
    let mut script_a = BTreeSet::new();
    let mut script_b = BTreeSet::new();

    let height1 = mine_regtest_block(tip, time + 1, 1, vec![]);
    let matured = height1.txdata[0].compute_txid();
    script_a.insert(matured.to_string());
    tip = height1.block_hash();
    time = height1.header.time;
    blocks.push(height1);

    let last_pad = maturity + 1;
    for height in 2..=last_pad {
        let block = mine_regtest_block(tip, time + 1, height, vec![]);
        script_a.insert(block.txdata[0].compute_txid().to_string());
        tip = block.block_hash();
        time = block.header.time;
        blocks.push(block);
    }

    let spend = spend_to(matured, Amount::from_sat(49_0000_0000), vec![0x52]);
    let spend_txid = spend.compute_txid().to_string();
    let spend_block = mine_regtest_block(tip, time + 1, last_pad + 1, vec![spend]);
    script_a.insert(spend_block.txdata[0].compute_txid().to_string());
    script_a.insert(spend_txid.clone());
    script_b.insert(spend_txid);
    blocks.push(spend_block);
    (blocks, script_a, script_b)
}

async fn start_miner(dir: &Path) -> P2PNode {
    let query = Query::open_or_create_tiny(dir.join("store")).unwrap();
    P2PNode::start(
        any_port(),
        query,
        ChainParams::regtest(),
        Milestone::NONE,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .expect("miner listen")
}

fn load_chain(miner: &P2PNode, blocks: &[bitcoin::Block]) {
    for (height, block) in blocks.iter().enumerate() {
        miner
            .ingest_block(block.clone())
            .unwrap_or_else(|e| panic!("ingest {height}: {e}"));
    }
}

fn syncer_cfg(dir: &Path, miner: SocketAddr) -> NodeConfig {
    syncer_cfg_sh(dir, miner, true)
}

// Every listener binds port 0. A bind-then-drop reserve raced the node's
// own P2P bind onto the RPC port, and the test then spoke HTTP to P2P.
fn syncer_cfg_sh(dir: &Path, miner: SocketAddr, shindex: bool) -> NodeConfig {
    let mut cfg = NodeConfig::default()
        .with_datadir(dir)
        .with_network(Network::Regtest)
        .with_p2p_listen(any_port())
        .with_tiny_heads();
    cfg.listen.connect = vec![NetAddr::Ip(miner)];
    cfg.listen.use_seeds = false;
    cfg.listen.electrum = Some(any_port());
    cfg.shindex = shindex;
    cfg.rpc.listen = Some(any_port());
    cfg.max_tip_age_secs = Some(u64::MAX);
    std::fs::write(dir.join("rpc.token"), "pass").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.join("rpc.token"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    cfg
}

fn published_path(dir: &Path, name: &str) -> PathBuf {
    dir.join("run").join(format!("{name}.addr"))
}

/// The address `run_p2p` bound for `name`, from `{datadir}/run/{name}.addr`.
async fn published_listener(dir: &Path, name: &str, wait: Duration) -> SocketAddr {
    let path = published_path(dir, name);
    let deadline = Instant::now() + wait;
    loop {
        let bound = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| text.trim().parse::<SocketAddr>().ok());
        if let Some(addr) = bound {
            return addr;
        }
        if Instant::now() >= deadline {
            panic!("{name} listener not up at {}", path.display());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_listeners(dir: &Path) -> (SocketAddr, SocketAddr) {
    let rpc = published_listener(dir, "rpc", Duration::from_secs(30)).await;
    let electrum = published_listener(dir, "electrum", Duration::from_secs(30)).await;
    (rpc, electrum)
}

/// A restart on the same datadir publishes fresh addresses; drop the last run's.
fn spawn_run_p2p(cfg: NodeConfig) -> tokio::task::JoinHandle<Result<(), rbitcoin_node::NodeError>> {
    match std::fs::remove_dir_all(cfg.datadir.path().join("run")) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("clear published listeners: {e}"),
    }
    tokio::task::spawn_blocking(move || {
        let _block = rbitcoin_net::BlockingRegion::enter();
        tokio::runtime::Handle::current().block_on(run_p2p(cfg))
    })
}

async fn jsonrpc(addr: SocketAddr, method: &str, params: Value) -> Value {
    rbitcoin_test::jsonrpc::jsonrpc(addr, method, params).await
}

/// `Err` only when the TCP connect fails, so a poll can retry it.
async fn try_jsonrpc(addr: SocketAddr, method: &str, params: Value) -> std::io::Result<Value> {
    rbitcoin_test::jsonrpc::try_jsonrpc(addr, method, params).await
}

async fn history_txids(electrum: SocketAddr, script: &[u8]) -> BTreeSet<String> {
    let mut stream = TcpStream::connect(electrum)
        .await
        .expect("electrum connect");
    let req = json!({
        "id": 1,
        "jsonrpc": "2.0",
        "method": "blockchain.scripthash.get_history",
        "params": [electrum_scripthash_hex(script)]
    })
    .to_string()
        + "\n";
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).await.unwrap();
    let hist: Value = serde_json::from_str(line.trim())
        .unwrap_or_else(|e| panic!("history json: {e} body={line}"));
    hist["result"]
        .as_array()
        .unwrap_or_else(|| panic!("{hist}"))
        .iter()
        .map(|row| {
            row["tx_hash"]
                .as_str()
                .unwrap_or_else(|| panic!("{row}"))
                .to_string()
        })
        .collect()
}

async fn stop_run_p2p(
    rpc: SocketAddr,
    node: tokio::task::JoinHandle<Result<(), rbitcoin_node::NodeError>>,
) {
    let _ = jsonrpc(rpc, "stop", json!([])).await;
    match tokio::time::timeout(Duration::from_secs(20), node).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => panic!("run_p2p error after stop: {e}"),
        Ok(Err(e)) => panic!("run_p2p join: {e}"),
        Err(_) => panic!("run_p2p did not exit after stop"),
    }
}

async fn wait_caught_up(
    rpc: SocketAddr,
    electrum: SocketAddr,
    height: u32,
    hash: &str,
    script_a: &BTreeSet<String>,
    script_b: &BTreeSet<String>,
) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let count = jsonrpc(rpc, "getblockcount", json!([])).await;
        let best = jsonrpc(rpc, "getbestblockhash", json!([])).await;
        let height_ok = count["result"].as_u64() == Some(u64::from(height));
        let hash_ok = best["result"].as_str() == Some(hash);
        let hist_a = history_txids(electrum, &[0x51]).await;
        let hist_b = history_txids(electrum, &[0x52]).await;
        if height_ok && hash_ok && &hist_a == script_a && &hist_b == script_b {
            return;
        }
        if Instant::now() >= deadline {
            panic!("catch-up count={count} best={best} A={hist_a:?} B={hist_b:?} want height={height} {hash}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn assert_tip_view(rpc: SocketAddr, height: u32, hash: &str) {
    let info = jsonrpc(rpc, "getblockchaininfo", json!([])).await;
    assert_eq!(
        info["result"]["initialblockdownload"], false,
        "caught up must leave IBD: {info}"
    );
    let tips = jsonrpc(rpc, "getchaintips", json!([])).await;
    let rows = tips["result"]
        .as_array()
        .unwrap_or_else(|| panic!("{tips}"));
    let active = rows
        .iter()
        .find(|tip| tip["status"] == "active")
        .unwrap_or_else(|| panic!("no active tip: {tips}"));
    assert_eq!(active["hash"].as_str(), Some(hash), "{tips}");
    assert_eq!(active["height"].as_u64(), Some(u64::from(height)), "{tips}");
}

fn pack_mark(store: &Path) -> PathBuf {
    let flat = store.join("scripthash.head.packed");
    if flat.is_file() {
        return flat;
    }
    let shard = store.join("scripthash.head").join("00.packed");
    assert!(
        shard.is_file(),
        "pack mark missing under {}",
        store.display()
    );
    shard
}

fn mark_mtime(path: &Path) -> SystemTime {
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("metadata {}: {e}", path.display()))
        .modified()
        .unwrap()
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for ent in std::fs::read_dir(src).unwrap() {
        let ent = ent.unwrap();
        let to = dst.join(ent.file_name());
        if ent.file_type().unwrap().is_dir() {
            copy_dir(&ent.path(), &to);
        } else {
            std::fs::copy(ent.path(), &to).unwrap();
        }
    }
}

fn store_tip(store: &Path) -> u32 {
    let query = Query::open_or_create_tiny(store).unwrap();
    query.tip_height().map(|h| h.0).unwrap_or(0)
}

/// Cancel IBD once the tip is in `(0, miner_tip)`. Returns that height.
async fn stop_ibd_below_tip(dir: &Path, miner: SocketAddr, miner_tip: u32) -> u32 {
    let query = Query::open_or_create_tiny(dir.join("store")).unwrap();
    let node = P2PNode::start(
        "127.0.0.1:0".parse().unwrap(),
        query,
        ChainParams::regtest(),
        Milestone::NONE,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .expect("partial syncer");
    let hub = Arc::clone(&node.hub);
    let tip = {
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancel);
        let peers = [NetAddr::Ip(miner)];
        let sync = rbitcoin_ibd::sync_cancellable(&node, &peers, IbdConfig::for_test(), Some(flag));
        tokio::pin!(sync);
        let mut saw_mid = false;
        let joined = loop {
            tokio::select! {
                result = &mut sync => break result,
                _ = tokio::time::sleep(Duration::from_millis(5)) => {
                    let height = hub.tip_height().unwrap_or(0);
                    if height > 0 && height < miner_tip {
                        saw_mid = true;
                        cancel.store(true, Ordering::SeqCst);
                    }
                }
            }
        };
        joined.expect("cancelled IBD still returns after teardown");
        let tip = hub.tip_height().unwrap_or(0);
        assert!(
            saw_mid && tip > 0 && tip < miner_tip,
            "IBD never observed below the miner tip (saw_mid={saw_mid} tip={tip} miner={miner_tip})"
        );
        tip
    };
    node.shutdown().await;
    tip
}

async fn expect_process_stays_up_without_electrum(
    node: tokio::task::JoinHandle<Result<(), rbitcoin_node::NodeError>>,
    dir: &Path,
) {
    let electrum = published_path(dir, "electrum");
    let rpc = published_listener(dir, "rpc", Duration::from_secs(30)).await;
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        assert!(
            !electrum.exists(),
            "Electrum listened before the chain was complete"
        );
        assert!(
            !node.is_finished(),
            "syncer with the miner down exited instead of waiting for peers"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    stop_run_p2p(rpc, node).await;
}

async fn extend_one(
    miner: &P2PNode,
    rpc: SocketAddr,
    electrum: SocketAddr,
    script_a: &mut BTreeSet<String>,
) -> (u32, String) {
    let before = history_txids(electrum, &[0x51]).await;
    miner
        .hub
        .generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let height = miner.tip_height().unwrap();
    let hash = miner.hub.tip_hash().unwrap().to_string();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let got = history_txids(electrum, &[0x51]).await;
        let count = jsonrpc(rpc, "getblockcount", json!([])).await;
        let best = jsonrpc(rpc, "getbestblockhash", json!([])).await;
        let added: BTreeSet<_> = got.difference(&before).cloned().collect();
        if count["result"].as_u64() == Some(u64::from(height))
            && best["result"].as_str() == Some(hash.as_str())
            && added.len() == 1
            && got.is_superset(&before)
        {
            script_a.extend(added);
            assert_eq!(&got, script_a);
            return (height, hash);
        }
        if Instant::now() >= deadline {
            panic!("tip-follow height={height} {hash} history={got:?} count={count} best={best}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn end_of_ibd_follow() {
    let wall = llvm_cov_wall(90, 180);
    tokio::time::timeout(wall, follow_journey())
        .await
        .expect("end_of_ibd_follow wall");
}

struct Synced {
    height: u32,
    hash: String,
    script_a: BTreeSet<String>,
    script_b: BTreeSet<String>,
}

async fn ibd_then_restart(miner: P2PNode, miner_addr: SocketAddr, synced: &mut Synced) {
    let syncer_dir = TestDatadir::new().unwrap();
    let dir = syncer_dir.path();
    let node = spawn_run_p2p(syncer_cfg(dir.as_path(), miner_addr));
    let (rpc, electrum) = wait_listeners(dir.as_path()).await;
    wait_caught_up(
        rpc,
        electrum,
        synced.height,
        &synced.hash,
        &synced.script_a,
        &synced.script_b,
    )
    .await;
    assert_tip_view(rpc, synced.height, &synced.hash).await;

    let (height, hash) = extend_one(&miner, rpc, electrum, &mut synced.script_a).await;
    synced.height = height;
    synced.hash = hash;
    assert_tip_view(rpc, synced.height, &synced.hash).await;

    let store = syncer_dir.store_path();
    let mark = pack_mark(&store);
    let packed_at = mark_mtime(&mark);
    assert!(!store.join("scripthash.unsorted").is_dir());
    stop_run_p2p(rpc, node).await;

    let node = spawn_run_p2p(syncer_cfg(dir.as_path(), miner_addr));
    let (rpc, electrum) = wait_listeners(dir.as_path()).await;
    wait_caught_up(
        rpc,
        electrum,
        synced.height,
        &synced.hash,
        &synced.script_a,
        &synced.script_b,
    )
    .await;
    assert_eq!(mark_mtime(&mark), packed_at, "restart collected again");
    assert!(!store.join("scripthash.unsorted").is_dir());
    let (height, hash) = extend_one(&miner, rpc, electrum, &mut synced.script_a).await;
    synced.height = height;
    synced.hash = hash;
    assert_eq!(
        mark_mtime(&mark),
        packed_at,
        "write-behind rewrote the pack mark"
    );
    assert_tip_view(rpc, synced.height, &synced.hash).await;

    miner.shutdown().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_tip_view(rpc, synced.height, &synced.hash).await;
    assert_eq!(history_txids(electrum, &[0x51]).await, synced.script_a);
    assert_eq!(history_txids(electrum, &[0x52]).await, synced.script_b);
    stop_run_p2p(rpc, node).await;
}

async fn finish_partial(dir: &Path, miner: SocketAddr, synced: &Synced) {
    let node = spawn_run_p2p(syncer_cfg(dir, miner));
    let (rpc, electrum) = wait_listeners(dir).await;
    wait_caught_up(
        rpc,
        electrum,
        synced.height,
        &synced.hash,
        &synced.script_a,
        &synced.script_b,
    )
    .await;
    assert_tip_view(rpc, synced.height, &synced.hash).await;
    stop_run_p2p(rpc, node).await;
}

async fn partial_with_miner_down(miner_dir: &Path, synced: &mut Synced) {
    let miner = start_miner(miner_dir).await;
    let miner_addr = miner.local_addr;
    assert_eq!(miner.tip_height().unwrap(), synced.height);
    assert_eq!(miner.hub.tip_hash().unwrap().to_string(), synced.hash);

    let partial_dir = TestDatadir::new().unwrap();
    let partial_tip =
        stop_ibd_below_tip(partial_dir.path().as_path(), miner_addr, synced.height).await;
    let held_dir = TestDatadir::new().unwrap();
    copy_dir(&partial_dir.store_path(), &held_dir.store_path());

    miner.shutdown().await;
    let held = spawn_run_p2p(syncer_cfg(held_dir.path().as_path(), miner_addr));
    expect_process_stays_up_without_electrum(held, held_dir.path().as_path()).await;
    let held_tip = store_tip(&held_dir.store_path());
    assert!(
        held_tip > 0 && held_tip < synced.height,
        "miner-down restart tip={held_tip} partial={partial_tip} full={}",
        synced.height
    );

    let miner = start_miner(miner_dir).await;
    finish_partial(partial_dir.path().as_path(), miner.local_addr, synced).await;
    finish_partial(held_dir.path().as_path(), miner.local_addr, synced).await;
    crash_with_class_a_above_tip(&miner, synced).await;
    miner.shutdown().await;
}

/// A crash between the Class A write and the tip advance leaves bodies above
/// the tip with no connect. The second block spends a create of the first and
/// one of its own, so the next start must fetch both and pin those parents
/// from the archive. The store holds catch-up indexes, as a crash in IBD does,
/// so a halted IBD has no tip-follow to fall back on.
async fn crash_with_class_a_above_tip(miner: &P2PNode, synced: &mut Synced) {
    let dir = TestDatadir::new().unwrap();
    let query = Query::open_or_create_tiny(dir.store_path()).unwrap();
    let node = P2PNode::start(
        any_port(),
        query,
        ChainParams::regtest(),
        Milestone::NONE,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .expect("crash syncer");
    let peers = [NetAddr::Ip(miner.local_addr)];
    rbitcoin_ibd::sync(&node, &peers, IbdConfig::for_test())
        .await
        .expect("crash syncer ibd");
    node.shutdown().await;

    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    let matured = miner
        .query
        .reconstruct_block_at_height(Height(2))
        .unwrap()
        .txdata[0]
        .compute_txid();
    let parent = spend_to(matured, Amount::from_sat(49_0000_0000), vec![0x51]);
    let child = spend_to(
        parent.compute_txid(),
        Amount::from_sat(48_0000_0000),
        vec![0x51],
    );
    let grandchild = spend_to(
        child.compute_txid(),
        Amount::from_sat(47_0000_0000),
        vec![0x51],
    );
    let mut blocks = Vec::new();
    for txs in [vec![parent], vec![child, grandchild]] {
        miner
            .hub
            .generate_to_script(1, op_true.clone(), txs)
            .unwrap();
        let block = miner
            .query
            .reconstruct_block_at_height(Height(miner.tip_height().unwrap()));
        blocks.push(Arc::new(block.unwrap()));
    }

    let query = Query::open_or_create_tiny(dir.store_path()).unwrap();
    let tip = query.tip_height();
    assert_eq!(tip, Some(Height(synced.height)));
    let mut prev_fk = query
        .get_header_by_hash(blocks[0].header.prev_blockhash.as_byte_array())
        .unwrap()
        .unwrap()
        .0;
    let mut fks = Vec::new();
    let mut txids = Vec::new();
    for block in &blocks {
        let hash = block.block_hash().to_byte_array();
        let rec = rbitcoin_query::header_to_record(prev_fk, &block.header, hash);
        prev_fk = query.ensure_header(&rec).unwrap();
        fks.push(prev_fk);
        let ids: Vec<[u8; 32]> = block
            .txdata
            .iter()
            .map(|t| t.compute_txid().to_byte_array())
            .collect();
        synced
            .script_a
            .extend(block.txdata.iter().map(|t| t.compute_txid().to_string()));
        txids.push(ids);
    }
    let items: Vec<_> = blocks
        .iter()
        .zip(&fks)
        .zip(&txids)
        .map(|((b, fk), ids)| (*fk, b, ids.as_slice()))
        .collect();
    query.archive_class_a_from_wire(&items).unwrap();
    query.flush().unwrap();
    assert_eq!(query.tip_height(), tip);
    synced.height = miner.tip_height().unwrap();
    synced.hash = miner.hub.tip_hash().unwrap().to_string();
    drop(query);
    finish_partial(dir.path().as_path(), miner.local_addr, synced).await;
}

async fn follow_journey() {
    let (blocks, script_a, script_b) = fixture_chain();
    let miner_dir = TestDatadir::new().unwrap();
    let miner = start_miner(miner_dir.path().as_path()).await;
    let miner_addr = miner.local_addr;
    load_chain(&miner, &blocks);
    let mut synced = Synced {
        height: miner.tip_height().unwrap(),
        hash: miner.hub.tip_hash().unwrap().to_string(),
        script_a,
        script_b,
    };
    assert_eq!(synced.height as usize, blocks.len() - 1);

    ibd_then_restart(miner, miner_addr, &mut synced).await;
    partial_with_miner_down(miner_dir.path().as_path(), &mut synced).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn end_of_ibd_sh_interrupt() {
    let wall = llvm_cov_wall(120, 240);
    tokio::time::timeout(wall, sh_interrupt_journey())
        .await
        .expect("end_of_ibd_sh_interrupt wall");
}

async fn wait_tip(rpc: SocketAddr, height: u32, hash: &str) {
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        let count = try_jsonrpc(rpc, "getblockcount", json!([])).await;
        let best = try_jsonrpc(rpc, "getbestblockhash", json!([])).await;
        if let (Ok(count), Ok(best)) = (count, best) {
            if count["result"].as_u64() == Some(u64::from(height))
                && best["result"].as_str() == Some(hash)
            {
                return;
            }
        }
        if Instant::now() >= deadline {
            panic!("shindex-off syncer did not reach height {height} {hash}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn catch_without_index(dir: &Path, miner: SocketAddr, height: u32, hash: &str) {
    let node = spawn_run_p2p(syncer_cfg_sh(dir, miner, false));
    let rpc = published_listener(dir, "rpc", Duration::from_secs(40)).await;
    wait_tip(rpc, height, hash).await;
    stop_run_p2p(rpc, node).await;
}

fn freeze_pass1(store: &Path) {
    let query = Query::open_or_create_tiny(store).unwrap();
    let n_shards = query.store().scripthash.head_shard_count();
    let udir = rbitcoin_store::unsorted_shard_dir(query.store().path());
    rbitcoin_store::collect_unsorted_shard_files(query.store(), &udir, n_shards, 1, None).unwrap();
    assert!(udir.join("DONE.keys").is_file(), "pass 1 writes DONE.keys");
    assert!(
        !udir.join("DONE.post").is_file(),
        "pass 1 stops before DONE.post"
    );
    assert!(
        !query.store().scripthash.has_durable_index(),
        "pass-1 mphf is not a packed head"
    );
    assert!(query.store().txs.count() > 1);
}

struct Resume {
    node: tokio::task::JoinHandle<Result<(), rbitcoin_node::NodeError>>,
    rpc: SocketAddr,
    electrum: SocketAddr,
}

async fn resume_until_history(
    dir: &Path,
    miner: SocketAddr,
    height: u32,
    hash: &str,
    script_a: &BTreeSet<String>,
    script_b: &BTreeSet<String>,
) -> Resume {
    let node = spawn_run_p2p(syncer_cfg_sh(dir, miner, true));
    let electrum = published_listener(dir, "electrum", Duration::from_secs(60)).await;
    let rpc = published_listener(dir, "rpc", Duration::from_secs(30)).await;
    // The port opens on the indexed tip. A block mined while the index was
    // built shows up after the follow headers round. Wait for that history.
    let deadline = Instant::now() + llvm_cov_wall(30, 60);
    loop {
        let hist_a = history_txids(electrum, &[0x51]).await;
        let hist_b = history_txids(electrum, &[0x52]).await;
        let count = try_jsonrpc(rpc, "getblockcount", json!([])).await.ok();
        let best = try_jsonrpc(rpc, "getbestblockhash", json!([])).await.ok();
        let tip_ok = count.as_ref().and_then(|v| v["result"].as_u64()) == Some(u64::from(height))
            && best.as_ref().and_then(|v| v["result"].as_str()) == Some(hash);
        if &hist_a == script_a && &hist_b == script_b && tip_ok {
            break;
        }
        if Instant::now() >= deadline {
            panic!(
                "scripthash history did not catch height {height}: A {}/{} B {}/{} tip={tip_ok}",
                hist_a.len(),
                script_a.len(),
                hist_b.len(),
                script_b.len()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_tip_view(rpc, height, hash).await;
    Resume {
        node,
        rpc,
        electrum,
    }
}

async fn resume_pass1_and_restart(
    dir: &Path,
    miner: SocketAddr,
    height: u32,
    hash: &str,
    script_a: &BTreeSet<String>,
    script_b: &BTreeSet<String>,
) -> SystemTime {
    let resumed = resume_until_history(dir, miner, height, hash, script_a, script_b).await;
    let store = dir.join("store");
    let mark = pack_mark(&store);
    let packed_at = mark_mtime(&mark);
    assert!(!store.join("scripthash.unsorted").is_dir());
    stop_run_p2p(resumed.rpc, resumed.node).await;

    let again = resume_until_history(dir, miner, height, hash, script_a, script_b).await;
    assert_eq!(mark_mtime(&mark), packed_at, "restart collected again");
    assert!(!store.join("scripthash.unsorted").is_dir());
    stop_run_p2p(again.rpc, again.node).await;
    packed_at
}

fn mine_one_a(miner: &P2PNode) -> (u32, String, String) {
    miner
        .hub
        .generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let height = miner.tip_height().unwrap();
    let hash = miner.hub.tip_hash().unwrap().to_string();
    let ids = miner.query.block_txids(Height(height)).unwrap();
    let txid: String = ids[0].iter().rev().map(|b| format!("{b:02x}")).collect();
    (height, hash, txid)
}

async fn contaminate_writebehind(dir: &Path, miner: &P2PNode, height: u32) {
    let block = miner
        .query
        .reconstruct_block_at_height(Height(height))
        .unwrap();
    let store = dir.join("store");
    let before = Query::open_or_create_tiny(&store)
        .unwrap()
        .store()
        .txs
        .count();
    let query = Query::open_or_create_tiny(&store).unwrap();
    let node = P2PNode::start(
        "127.0.0.1:0".parse().unwrap(),
        query,
        ChainParams::regtest(),
        Milestone::NONE,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .expect("contaminated syncer");
    node.ingest_block(block)
        .unwrap_or_else(|e| panic!("write-behind ingest: {e}"));
    let count = node.query.store().txs.count();
    assert!(count > before, "ingested block did not grow Class A");
    assert!(
        !node.query.store().scripthash.has_durable_index(),
        "write-behind on a pass-1 head must not pack it"
    );
    if node.query.store().scripthash.include_hwm() < count {
        let fk = Fk(count);
        let rec = ScriptHashRecord::from_fk(script_hash(&[0x51]), fk);
        let mut heads = std::collections::HashMap::new();
        node.query
            .store()
            .scripthash
            .put_create_batch_append(&[rec], &mut heads)
            .unwrap();
        std::fs::write(
            store.join(rbitcoin_store::INCLUDE_HWM_NAME),
            count.to_le_bytes(),
        )
        .unwrap();
    }
    let udir = store.join("scripthash.unsorted");
    assert!(udir.join("DONE.keys").is_file());
    assert!(!udir.join("DONE.post").is_file());
    node.shutdown().await;
    let query = Query::open_or_create_tiny(&store).unwrap();
    assert!(!query.store().scripthash.has_durable_index());
    assert_eq!(query.store().scripthash.include_hwm(), count);
}

async fn sh_interrupt_journey() {
    let (blocks, script_a, script_b) = fixture_chain();
    let miner_dir = TestDatadir::new().unwrap();
    let miner = start_miner(miner_dir.path().as_path()).await;
    let miner_addr = miner.local_addr;
    load_chain(&miner, &blocks);
    let height = miner.tip_height().unwrap();
    let hash = miner.hub.tip_hash().unwrap().to_string();
    assert_eq!(height as usize, blocks.len() - 1);

    let frozen = TestDatadir::new().unwrap();
    catch_without_index(frozen.path().as_path(), miner_addr, height, &hash).await;
    freeze_pass1(&frozen.store_path());
    let gap = TestDatadir::new().unwrap();
    let lie = TestDatadir::new().unwrap();
    copy_dir(&frozen.store_path(), &gap.store_path());
    copy_dir(&frozen.store_path(), &lie.store_path());

    let packed_at = resume_pass1_and_restart(
        frozen.path().as_path(),
        miner_addr,
        height,
        &hash,
        &script_a,
        &script_b,
    )
    .await;

    let (new_height, new_hash, txid) = mine_one_a(&miner);
    let mut with_new = script_a.clone();
    with_new.insert(txid);
    let resumed = resume_until_history(
        gap.path().as_path(),
        miner_addr,
        new_height,
        &new_hash,
        &with_new,
        &script_b,
    )
    .await;
    stop_run_p2p(resumed.rpc, resumed.node).await;

    contaminate_writebehind(lie.path().as_path(), &miner, new_height).await;
    let resumed = resume_until_history(
        lie.path().as_path(),
        miner_addr,
        new_height,
        &new_hash,
        &with_new,
        &script_b,
    )
    .await;
    stop_run_p2p(resumed.rpc, resumed.node).await;

    let mark = pack_mark(&frozen.store_path());
    let resumed = resume_until_history(
        frozen.path().as_path(),
        miner_addr,
        new_height,
        &new_hash,
        &with_new,
        &script_b,
    )
    .await;
    assert_eq!(
        mark_mtime(&mark),
        packed_at,
        "write-behind rewrote the pack mark"
    );
    assert_eq!(history_txids(resumed.electrum, &[0x51]).await, with_new);
    stop_run_p2p(resumed.rpc, resumed.node).await;
    miner.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn end_of_ibd_work_fork() {
    let wall = llvm_cov_wall(30, 90);
    tokio::time::timeout(wall, work_fork_journey())
        .await
        .expect("end_of_ibd_work_fork wall");
}

fn fork_params() -> ChainParams {
    let mut params = ChainParams::regtest();
    let spacing = params.btc.pow_target_spacing;
    params.btc.no_pow_retargeting = false;
    params.btc.allow_min_difficulty_blocks = true;
    params.btc.pow_target_timespan = spacing.saturating_mul(20);
    params
}

fn expected_bits(
    params: &ChainParams,
    height: u32,
    chain: &[bitcoin::Block],
    time: u32,
) -> CompactTarget {
    let prev = &chain[(height - 1) as usize].header;
    let interval = params.difficulty_adjustment_interval();
    let first = if interval > 0 && height.is_multiple_of(interval) && !params.no_pow_retargeting() {
        Some(chain[(height - interval) as usize].header.time)
    } else {
        None
    };
    next_work_bits(params, height, prev.bits, prev.time, time, first, |h| {
        chain.get(h as usize).map(|block| block.header.bits)
    })
    .expect("next bits")
}

fn chain_work(blocks: &[bitcoin::Block]) -> Work {
    blocks
        .iter()
        .fold(Work::from_be_bytes([0u8; 32]), |acc, block| {
            acc + block.header.work()
        })
}

fn push_block(params: &ChainParams, chain: &mut Vec<bitcoin::Block>, time: u32) {
    let height = chain.len() as u32;
    let bits = expected_bits(params, height, chain, time);
    let prev = chain.last().unwrap().block_hash();
    chain.push(mine_regtest_block_at(prev, time, height, bits, vec![]));
}

fn build_forks(params: &ChainParams) -> (Vec<bitcoin::Block>, Vec<bitcoin::Block>) {
    let mut heavy = vec![regtest_genesis()];
    let mut time = heavy[0].header.time;
    for _ in 1..=89 {
        time = time.saturating_add(1);
        push_block(params, &mut heavy, time);
    }
    let mut light = heavy[..=20].to_vec();
    let step = (params.btc.pow_target_spacing as u32).saturating_mul(2) + 1;
    for _ in 21..=90 {
        let prev_time = light.last().unwrap().header.time;
        push_block(params, &mut light, prev_time.saturating_add(step));
    }
    (heavy, light)
}

async fn start_node(dir: &Path, params: ChainParams) -> P2PNode {
    let query = Query::open_or_create_tiny(dir.join("store")).unwrap();
    let node = P2PNode::start(
        any_port(),
        query,
        params,
        Milestone::NONE,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .expect("listen");
    node.hub.set_max_tip_age_secs(u64::MAX);
    node
}

async fn sync_heavy(
    dir: &Path,
    params: ChainParams,
    peers: [SocketAddr; 2],
    height: u32,
    hash: BlockHash,
) {
    let node = start_node(dir, params).await;
    rbitcoin_ibd::sync(
        &node,
        &[NetAddr::Ip(peers[0]), NetAddr::Ip(peers[1])],
        IbdConfig::for_test(),
    )
    .await
    .expect("sync heavier fork");
    assert_eq!(
        node.tip_height(),
        Some(height),
        "syncer left the heavier tip"
    );
    assert_eq!(node.hub.tip_hash().unwrap(), hash);
    node.shutdown().await;
}

async fn replay_full_fork(
    dir: &Path,
    params: ChainParams,
    light: &[bitcoin::Block],
    height: u32,
    tip: BlockHash,
) {
    use bitcoin::p2p::{message::NetworkMessage, Magic};
    use rbitcoin_net::peer::{connect_and_handshake, HandshakePolicy};
    use rbitcoin_net::v2::{read_v2_frame, write_v2_msg};

    let mut fork = light.to_vec();
    let window = rbitcoin_net::codec::MAX_HEADERS_RESULTS;
    let end = 20 + 2 * window;
    let step = (params.btc.pow_target_spacing as u32) * 2 + 1;
    while fork.len() <= end {
        let time = fork.last().unwrap().header.time + step;
        push_block(&params, &mut fork, time);
    }
    let batches: [Vec<_>; 2] = std::array::from_fn(|i| {
        fork[21 + i * window..21 + (i + 1) * window]
            .iter()
            .map(|block| block.header)
            .collect()
    });
    let fork_tips = batches
        .each_ref()
        .map(|batch| batch.last().unwrap().block_hash());
    let listener = tokio::net::TcpListener::bind(any_port()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let node = start_node(dir, params).await;
    assert!(chain_work(&fork) < node.hub.chain_work().unwrap());
    let peer = tokio::spawn(async move {
        let (stream, remote) = listener.accept().await.unwrap();
        let (_, mut reader, mut writer, _, _tcp) = connect_and_handshake(
            stream,
            Magic::REGTEST,
            addr,
            remote,
            100_000,
            true,
            "/full-header-replay/",
            HandshakePolicy::plain(),
        )
        .await
        .unwrap();
        let mut replies = 0;
        while let Ok(frame) = read_v2_frame(&mut reader, Magic::REGTEST).await {
            let response = match frame.decode().payload() {
                NetworkMessage::GetHeaders(request) => {
                    if replies == 0 {
                        assert_eq!(request.locator_hashes[0], tip);
                    } else {
                        assert!(
                            request
                                .locator_hashes
                                .contains(&fork_tips[(replies - 1).min(1)]),
                            "each full lighter-fork window must get a continuation request"
                        );
                    }
                    let response = NetworkMessage::Headers(batches[replies.min(1)].clone());
                    replies += 1;
                    response
                }
                NetworkMessage::Ping(nonce) => NetworkMessage::Pong(*nonce),
                NetworkMessage::GetData(items) => NetworkMessage::NotFound(items.clone()),
                _ => continue,
            };
            if write_v2_msg(&mut writer, response).await.is_err() {
                break;
            }
        }
        replies
    });
    let result = tokio::time::timeout(
        llvm_cov_wall(5, 20),
        rbitcoin_ibd::sync(&node, &[NetAddr::Ip(addr)], IbdConfig::for_test()),
    )
    .await;
    let actual_tip = (node.tip_height(), node.hub.tip_hash());
    node.shutdown().await;
    assert!(
        result.is_ok(),
        "replayed full headers must not keep the validated tip in IBD"
    );
    result
        .unwrap()
        .expect("finish IBD despite advertised height");
    assert_eq!(actual_tip, (Some(height), Some(tip)));
    assert!(
        peer.await.unwrap() >= 3,
        "the peer must extend the lighter fork, then replay its second full window"
    );
}

async fn work_fork_journey() {
    let params = fork_params();
    let (mut heavy_blocks, mut light_blocks) = build_forks(&params);
    let heavy_h = (heavy_blocks.len() - 1) as u32;
    let light_h = (light_blocks.len() - 1) as u32;
    assert!(light_h > heavy_h);
    assert!(chain_work(&light_blocks) < chain_work(&heavy_blocks));
    assert_ne!(
        heavy_blocks.last().unwrap().header.bits,
        light_blocks.last().unwrap().header.bits
    );

    let heavy_dir = TestDatadir::new().unwrap();
    let light_dir = TestDatadir::new().unwrap();
    let heavy = start_node(heavy_dir.path().as_path(), params.clone()).await;
    let light = start_node(light_dir.path().as_path(), params.clone()).await;
    load_chain(&heavy, &heavy_blocks);
    load_chain(&light, &light_blocks);
    assert!(
        light.hub.work_through_height(light_h).unwrap()
            < heavy.hub.work_through_height(heavy_h).unwrap()
    );
    let heavy_hash = heavy.hub.tip_hash().unwrap();
    let syncer = TestDatadir::new().unwrap();
    let peers = [heavy.local_addr, light.local_addr];
    sync_heavy(
        syncer.path().as_path(),
        params.clone(),
        peers,
        heavy_h,
        heavy_hash,
    )
    .await;
    sync_heavy(
        syncer.path().as_path(),
        params.clone(),
        peers,
        heavy_h,
        heavy_hash,
    )
    .await;

    replay_full_fork(
        syncer.path().as_path(),
        params.clone(),
        &light_blocks,
        heavy_h,
        heavy_hash,
    )
    .await;

    let heavy_time = heavy_blocks.last().unwrap().header.time.saturating_add(1);
    push_block(&params, &mut heavy_blocks, heavy_time);
    heavy
        .ingest_block(heavy_blocks.last().unwrap().clone())
        .unwrap();
    let step = (params.btc.pow_target_spacing as u32).saturating_mul(2) + 1;
    for _ in 0..3 {
        let prev_time = light_blocks.last().unwrap().header.time;
        push_block(&params, &mut light_blocks, prev_time.saturating_add(step));
        light
            .ingest_block(light_blocks.last().unwrap().clone())
            .unwrap();
    }
    let heavy_h = (heavy_blocks.len() - 1) as u32;
    let light_h = (light_blocks.len() - 1) as u32;
    assert!(light_h > heavy_h);
    assert!(chain_work(&light_blocks) < chain_work(&heavy_blocks));
    let heavy_hash = heavy.hub.tip_hash().unwrap();
    sync_heavy(syncer.path().as_path(), params, peers, heavy_h, heavy_hash).await;
    heavy.shutdown().await;
    light.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn end_of_ibd_invalid_heavier_fork() {
    // Five serial syncs. Under llvm-cov each may use 60s, so the wall has to
    // cover 300s plus startup.
    let wall = llvm_cov_wall(60, 360);
    tokio::time::timeout(wall, invalid_heavier_fork_journey())
        .await
        .expect("end_of_ibd_invalid_heavier_fork wall");
}

/// The subsidy halves at this height for the syncer and the honest miners.
const SPLIT_HALVING: u32 = 20;

fn split_params() -> ChainParams {
    let mut params = ChainParams::regtest();
    params.overlay_subsidy_halving_interval(SPLIT_HALVING);
    params
}

/// Extend `chain` to `top`. Blocks at or past [`SPLIT_HALVING`] pay 25 BTC
/// when `halved`; a miner that never halves pays 50 BTC there, which the
/// syncer rejects as coinbase excess. `skew` keeps sibling hashes apart.
fn extend_split(chain: &mut Vec<bitcoin::Block>, top: u32, halved: bool, skew: u32) {
    while (chain.len() as u32) <= top {
        let height = chain.len() as u32;
        let prev = chain.last().unwrap();
        let time = prev.header.time.saturating_add(1).saturating_add(skew);
        let mut block = mine_regtest_block(prev.block_hash(), time, height, vec![]);
        if halved && height >= SPLIT_HALVING {
            block.txdata[0] = coinbase_tx(height, Amount::from_sat(25_0000_0000));
            block.header.merkle_root = block.compute_merkle_root().unwrap();
            rbitcoin_consensus::grind_regtest_pow(&mut block.header);
        }
        chain.push(block);
    }
}

/// Sync `dir` from `peers`; IBD must return at `tip`.
async fn sync_to(dir: &Path, peers: &[SocketAddr], tip: &bitcoin::Block, height: u32, beat: &str) {
    let node = start_node(dir, split_params()).await;
    let addrs: Vec<NetAddr> = peers.iter().copied().map(NetAddr::Ip).collect();
    tokio::time::timeout(
        llvm_cov_wall(20, 60),
        rbitcoin_ibd::sync(&node, &addrs, IbdConfig::for_test()),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{beat}: IBD did not return (tip {:?}, want {height})",
            node.tip_height()
        )
    })
    .unwrap_or_else(|e| panic!("{beat}: sync: {e}"));
    assert_eq!(node.tip_height(), Some(height), "{beat}: tip height");
    assert_eq!(
        node.hub.tip_hash(),
        Some(tip.block_hash()),
        "{beat}: tip hash"
    );
    node.shutdown().await;
}

async fn invalid_heavier_fork_journey() {
    // `split` never halves, so from SPLIT_HALVING on its chain is invalid to
    // the syncer while it carries the most header work. `honest` forks below
    // the halving; `at_fork` forks at the first invalid block.
    let mut split_blocks = vec![regtest_genesis()];
    extend_split(&mut split_blocks, 40, false, 0);
    let mut honest_blocks = split_blocks[..=14].to_vec();
    extend_split(&mut honest_blocks, 17, true, 1_000);
    let mut at_fork_blocks = split_blocks[..SPLIT_HALVING as usize].to_vec();
    extend_split(&mut at_fork_blocks, 30, true, 2_000);

    let split_dir = TestDatadir::new().unwrap();
    let honest_dir = TestDatadir::new().unwrap();
    let at_fork_dir = TestDatadir::new().unwrap();
    let split = start_node(split_dir.path().as_path(), ChainParams::regtest()).await;
    let honest = start_node(honest_dir.path().as_path(), split_params()).await;
    let at_fork = start_node(at_fork_dir.path().as_path(), split_params()).await;
    load_chain(&split, &split_blocks);
    load_chain(&honest, &honest_blocks);
    load_chain(&at_fork, &at_fork_blocks);

    // The split chain's valid prefix (to 19) has more work than honest (17).
    let syncer = TestDatadir::new().unwrap();
    let pair = [split.local_addr, honest.local_addr];
    let valid_top = &split_blocks[SPLIT_HALVING as usize - 1];
    sync_to(
        syncer.path().as_path(),
        &pair,
        valid_top,
        SPLIT_HALVING - 1,
        "valid prefix",
    )
    .await;

    // Once honest outgrows that prefix, a syncer that confirmed the prefix
    // leaves it for the honest chain.
    let from = honest_blocks.len() as u32;
    extend_split(&mut honest_blocks, 30, true, 1_000);
    for block in honest_blocks.iter().skip(from as usize) {
        honest.ingest_block(block.clone()).unwrap();
    }
    let rewinds = TestDatadir::new().unwrap();
    sync_to(
        rewinds.path().as_path(),
        &pair,
        honest_blocks.last().unwrap(),
        30,
        "heavier honest",
    )
    .await;

    // The syncer that kept the prefix restarts. The invalid block stays
    // invalid, so the split headers stored above it are not a path.
    let honest_tip = honest_blocks.last().unwrap();
    sync_to(syncer.path().as_path(), &pair, honest_tip, 30, "restart").await;
    sync_to(
        syncer.path().as_path(),
        &[honest.local_addr],
        honest_tip,
        30,
        "restart with only honest",
    )
    .await;

    // A fork at the first invalid block: nothing on the split side to keep.
    let fresh = TestDatadir::new().unwrap();
    sync_to(
        fresh.path().as_path(),
        &[split.local_addr, at_fork.local_addr],
        at_fork_blocks.last().unwrap(),
        30,
        "fork at the invalid block",
    )
    .await;
    split.shutdown().await;
    honest.shutdown().await;
    at_fork.shutdown().await;
}

fn startup_cfg(dir: &Path, miner: SocketAddr, max_tip_age: u64) -> NodeConfig {
    let mut cfg = NodeConfig::default()
        .with_datadir(dir)
        .with_network(Network::Regtest)
        .with_p2p_listen(any_port())
        .with_tiny_heads();
    cfg.listen.connect = vec![NetAddr::Ip(miner)];
    cfg.listen.use_seeds = false;
    cfg.shindex = false;
    cfg.rpc.listen = Some(any_port());
    cfg.max_tip_age_secs = Some(max_tip_age);
    std::fs::write(dir.join("rpc.token"), "pass").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.join("rpc.token"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    cfg
}

fn regtest_chain(blocks: u32) -> Vec<bitcoin::Block> {
    let genesis = regtest_genesis();
    let mut out = vec![genesis.clone()];
    let mut tip = genesis.block_hash();
    let mut time = genesis.header.time;
    for height in 1..=blocks {
        let block = mine_regtest_block(tip, time.saturating_add(1), height, vec![]);
        tip = block.block_hash();
        time = block.header.time;
        out.push(block);
    }
    out
}

/// One difficulty-1 header under genesis. Its work beats a long easy regtest chain.
fn plant_deep_heavy_header(q: &Query) -> [u8; 32] {
    use rbitcoin_store::{block_header_hash, HeaderRecord};
    let (gfk, genesis) = q.header_at_height(Height(0)).unwrap().unwrap();
    let version = 1i32;
    let bits = 0x1d00_ffffu32;
    let timestamp = genesis.timestamp.saturating_add(1);
    let nonce = 9u32;
    let merkle_root = [0x5a; 32];
    let hash = block_header_hash(version, &genesis.hash, &merkle_root, timestamp, bits, nonce);
    q.put_header(&HeaderRecord {
        prev_fk: gfk,
        version,
        timestamp,
        bits,
        nonce,
        merkle_root,
        hash,
        size: 0,
        weight: 0,
    })
    .unwrap();
    hash
}

type StartupLogs = Vec<(rbitcoin_log::Level, String)>;

fn spawn_run_p2p_logs(
    cfg: NodeConfig,
) -> tokio::task::JoinHandle<(Result<(), rbitcoin_node::NodeError>, StartupLogs)> {
    match std::fs::remove_dir_all(cfg.datadir.path().join("run")) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("clear published listeners: {e}"),
    }
    tokio::task::spawn_blocking(move || {
        let _block = rbitcoin_net::BlockingRegion::enter();
        rbitcoin_log::capture_logs(true);
        let result = tokio::runtime::Handle::current().block_on(run_p2p(cfg));
        let logs = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        (result, logs)
    })
}

async fn stop_logged(
    rpc: SocketAddr,
    node: tokio::task::JoinHandle<(Result<(), rbitcoin_node::NodeError>, StartupLogs)>,
) -> StartupLogs {
    let _ = jsonrpc(rpc, "stop", json!([])).await;
    match tokio::time::timeout(Duration::from_secs(20), node).await {
        Ok(Ok((Ok(()), logs))) => logs,
        Ok(Ok((Err(e), _))) => panic!("run_p2p error after stop: {e}"),
        Ok(Err(e)) => panic!("run_p2p join: {e}"),
        Err(_) => panic!("run_p2p did not exit after stop"),
    }
}

async fn wait_height(rpc: SocketAddr, height: u32) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let count = jsonrpc(rpc, "getblockcount", json!([])).await;
        if count["result"].as_u64() == Some(u64::from(height)) {
            return;
        }
        if Instant::now() >= deadline {
            panic!("height {height} not reached: {count}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn assert_startup(logs: &StartupLogs, skip: bool) {
    let skipped = logs
        .iter()
        .any(|(_, line)| line.contains("stored tip is current"));
    let catch_up = logs
        .iter()
        .any(|(_, line)| line.contains("ibd: catch-up candidates"));
    assert_eq!(
        skipped,
        skip,
        "skip={skip} lines={:?}",
        logs.iter().map(|(_, line)| line).collect::<Vec<_>>()
    );
    assert_eq!(catch_up, !skip, "catch-up log did not match skip={skip}");
}

/// Restart above genesis with the miner ahead: tip follow, no catch-up dial.
/// A stale max tip age, and a heavier header forked under genesis on a
/// 40-block chain, both stay in catch-up. Genesis itself stays in catch-up
/// in `node_run_p2p_short`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn startup_tip_follow_on_restart() {
    let wall = llvm_cov_wall(60, 180);
    tokio::time::timeout(wall, startup_tip_follow_journey())
        .await
        .expect("startup_tip_follow_on_restart wall");
}

async fn startup_tip_follow_journey() {
    let blocks = regtest_chain(7);
    let miner_dir = TestDatadir::new().unwrap();
    let miner = start_miner(miner_dir.path().as_path()).await;
    load_chain(&miner, &blocks);
    let syncer_dir = TestDatadir::new().unwrap();
    let syncer = start_miner(syncer_dir.path().as_path()).await;
    load_chain(&syncer, &blocks[..=5]);
    syncer.hub.query.flush().unwrap();
    syncer.shutdown().await;

    let node = spawn_run_p2p_logs(startup_cfg(
        syncer_dir.path().as_path(),
        miner.local_addr,
        u64::MAX,
    ));
    let rpc = published_listener(syncer_dir.path().as_path(), "rpc", Duration::from_secs(30)).await;
    wait_height(rpc, 7).await;
    let logs = stop_logged(rpc, node).await;
    assert_startup(&logs, true);

    let node = spawn_run_p2p_logs(startup_cfg(
        syncer_dir.path().as_path(),
        miner.local_addr,
        0,
    ));
    let rpc = published_listener(syncer_dir.path().as_path(), "rpc", Duration::from_secs(30)).await;
    wait_height(rpc, 7).await;
    let logs = stop_logged(rpc, node).await;
    assert_startup(&logs, false);

    // 40 blocks puts the genesis sibling outside the 32-hop IBD seed window.
    let deep = regtest_chain(40);
    let deep_miner_dir = TestDatadir::new().unwrap();
    let deep_miner = start_miner(deep_miner_dir.path().as_path()).await;
    load_chain(&deep_miner, &deep);
    let deep_dir = TestDatadir::new().unwrap();
    let deep_node = start_miner(deep_dir.path().as_path()).await;
    load_chain(&deep_node, &deep);
    let heavy = plant_deep_heavy_header(&deep_node.hub.query);
    deep_node.hub.query.flush().unwrap();
    deep_node.shutdown().await;

    let node = spawn_run_p2p_logs(startup_cfg(
        deep_dir.path().as_path(),
        deep_miner.local_addr,
        u64::MAX,
    ));
    let rpc = published_listener(deep_dir.path().as_path(), "rpc", Duration::from_secs(30)).await;
    wait_height(rpc, 40).await;
    let logs = stop_logged(rpc, node).await;
    assert_startup(&logs, false);

    // The same heavier header, once a connect failure marked it invalid, is
    // not a chain to catch up to.
    let mut marks = b"rbtcinv1".to_vec();
    marks.extend_from_slice(&1u32.to_le_bytes());
    marks.extend_from_slice(&heavy);
    std::fs::write(deep_dir.path().join("store").join("block.invalid"), marks).unwrap();
    let node = spawn_run_p2p_logs(startup_cfg(
        deep_dir.path().as_path(),
        deep_miner.local_addr,
        u64::MAX,
    ));
    let rpc = published_listener(deep_dir.path().as_path(), "rpc", Duration::from_secs(30)).await;
    wait_height(rpc, 40).await;
    let logs = stop_logged(rpc, node).await;
    assert_startup(&logs, true);

    deep_miner.shutdown().await;
    miner.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn assumehot_import_then_follow() {
    let wall = llvm_cov_wall(60, 180);
    tokio::time::timeout(wall, assumehot_journey())
        .await
        .expect("assumehot_import_then_follow wall");
}

/// A syncs the fixture and stops cleanly. B imports A's store with no peer
/// (so only the import can give it the chain and history), then restarts on
/// the miner, fills the block it missed and follows the next one.
async fn assumehot_journey() {
    let (blocks, mut script_a, script_b) = fixture_chain();
    let miner_dir = TestDatadir::new().unwrap();
    let miner = start_miner(miner_dir.path().as_path()).await;
    let miner_addr = miner.local_addr;
    load_chain(&miner, &blocks);
    let height = miner.tip_height().unwrap();
    let hash = miner.hub.tip_hash().unwrap().to_string();

    let a_dir = TestDatadir::new().unwrap();
    let a = a_dir.path();
    let node = spawn_run_p2p(syncer_cfg(a.as_path(), miner_addr));
    let (rpc, electrum) = wait_listeners(a.as_path()).await;
    wait_caught_up(rpc, electrum, height, &hash, &script_a, &script_b).await;
    stop_run_p2p(rpc, node).await;
    let digest = Query::open_or_create_tiny(a_dir.store_path())
        .unwrap()
        .hot_digest()
        .unwrap()
        .expect("source digest");
    assert_eq!(digest.height, height);

    let b_dir = TestDatadir::new().unwrap();
    let b = b_dir.path();
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let mut cfg = syncer_cfg(b.as_path(), dead);
    cfg.assumehot = Some((a.to_path_buf(), digest.digest));
    let node = spawn_run_p2p(cfg);
    let (rpc, electrum) = wait_listeners(b.as_path()).await;
    wait_caught_up(rpc, electrum, height, &hash, &script_a, &script_b).await;
    stop_run_p2p(rpc, node).await;
    assert!(!b.join("store.import").exists());

    let last = blocks.last().unwrap();
    let missed = mine_regtest_block(last.block_hash(), last.header.time + 1, height + 1, vec![]);
    script_a.insert(missed.txdata[0].compute_txid().to_string());
    miner.ingest_block(missed).unwrap();
    let height = miner.tip_height().unwrap();
    let hash = miner.hub.tip_hash().unwrap().to_string();
    let node = spawn_run_p2p(syncer_cfg(b.as_path(), miner_addr));
    let (rpc, electrum) = wait_listeners(b.as_path()).await;
    wait_caught_up(rpc, electrum, height, &hash, &script_a, &script_b).await;
    let (height, hash) = extend_one(&miner, rpc, electrum, &mut script_a).await;
    assert_tip_view(rpc, height, &hash).await;
    assert_eq!(history_txids(electrum, &[0x52]).await, script_b);
    stop_run_p2p(rpc, node).await;
    miner.shutdown().await;
}
