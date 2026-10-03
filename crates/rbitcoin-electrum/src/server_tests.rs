use super::*;
use rbitcoin_consensus::ChainParams;
use rbitcoin_query::testutil::FixtureChain;

use rbitcoin_query::Query;
use std::collections::{HashMap, HashSet};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

fn tmp_store() -> (rbitcoin_query::testutil::TempDir, Query) {
    rbitcoin_query::testutil::tiny_query_labeled("electrum")
}

#[allow(clippy::cognitive_complexity)] // one fixture, many parser arms
#[test]
fn config_helpers_and_param_parsers() {
    let params = ChainParams::regtest();
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    assert_eq!(
        cfg.genesis_hash_hex,
        rbitcoin_primitives::display_hash_hex(&params.genesis_hash.to_byte_array())
    );
    assert!(cfg.banner.contains("rbitcoin"));
    assert_eq!(cfg.tweaks_chunk, crate::tweaks::SUBSCRIBE_CHUNK);
    assert_eq!(cfg.tweaks_min_dust, crate::tweaks::DEFAULT_TWEAKS_MIN_DUST);

    let sh = electrum_scripthash_hex(&[0x51]);
    assert_eq!(sh.len(), 64);

    assert_eq!(param_u32(&json!([3]), 0).unwrap(), 3);
    assert_eq!(param_u32(&json!(["7"]), 0).unwrap(), 7);
    assert!(param_u32(&json!([]), 0).is_err());
    assert!(param_u32(&json!([true]), 0).is_err());
    assert!(param_u32(&json!([Value::Null]), 0).is_err());
    assert!(param_u32(&json!({"0": 1}), 0).is_err());
    assert!(param_u32(&json!([1.5]), 0).is_err());
    assert!(
        param_u32(&json!([1u64 << 32]), 0).is_err(),
        "u32 overflow must not wrap"
    );
    assert_eq!(param_u32(&json!([u32::MAX as u64]), 0).unwrap(), u32::MAX);
    assert!(param_i64(&json!([true]), 0).is_err());
    assert!(param_str(&json!([false]), 0).is_err());
    assert!(param_str(&json!({}), 0).is_err());
    assert!(parse_electrum_request_line("{").is_none());
    assert!(parse_electrum_request_line("").is_none());
    assert!(parse_electrum_request_line("not-json").is_none());
    let ping_line = parse_electrum_request_line(r#"{"id":1,"method":"server.ping"}"#).unwrap();
    assert_eq!(ping_line["method"], "server.ping");
    assert!(parse_electrum_request_line("[1]").unwrap().is_array());
    assert_eq!(param_i64(&json!([-1]), 0).unwrap(), -1);
    assert_eq!(param_i64(&json!(["10"]), 0).unwrap(), 10);
    assert_eq!(param_str(&json!(["hi"]), 0).unwrap(), "hi");
    assert!(param_str(&json!([1]), 0).is_err());

    let (dir, q) = tmp_store();
    q.set_sh_index_enabled(false);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let mut header_sub = false;
    let mut sh_subs = HashSet::new();
    let sh = electrum_scripthash_hex(&[0x51]);
    let err = dispatch(
        "blockchain.scripthash.get_balance",
        &json!([sh]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap_err();
    assert_eq!(err, rbitcoin_query::SCRIPTHASH_INDEX_DISABLED);
    let ping = dispatch(
        "server.ping",
        &json!([]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert_eq!(ping, Value::Null);
    let _ = std::fs::remove_dir_all(&dir);

    let mut sh_bytes = [0u8; 32];
    sh_bytes[0] = 0xaa;
    let sh_hex = hash_hex_rev(&sh_bytes);
    let parsed = param_scripthash(&json!([sh_hex]), 0).unwrap();
    assert_eq!(parsed, sh_bytes);
    assert!(param_scripthash(&json!(["aa"]), 0).is_err());

    let tid = param_txid(&json!([sh_hex]), 0).unwrap();
    assert_eq!(tid, sh_bytes);
    assert!(param_txid(&json!(["aabb"]), 0).is_err());
    assert!(param_txid(&json!(["zz".repeat(32)]), 0).is_err());

    // get_history window: 1-arg open + mempool; finite to excludes mempool.
    let (f, mp) = parse_get_history_window(&json!([sh_hex])).unwrap();
    assert_eq!(f.from_height, 0);
    assert!(f.to_height.is_none());
    assert!(mp);
    let (f, mp) = parse_get_history_window(&json!([sh_hex, 5])).unwrap();
    assert_eq!(f.from_height, 5);
    assert!(f.to_height.is_none());
    assert!(mp);
    let (f, mp) = parse_get_history_window(&json!([sh_hex, 2, -1])).unwrap();
    assert_eq!(f.from_height, 2);
    assert!(f.to_height.is_none());
    assert!(mp);
    let (f, mp) = parse_get_history_window(&json!([sh_hex, 1, 10])).unwrap();
    assert_eq!(f.from_height, 1);
    assert_eq!(f.to_height, Some(10));
    assert!(!mp);
    let asof_hex = "ab".repeat(32);
    let tagged = format!("asof:{asof_hex}");
    let (rest, h) = take_trailing_asof(
        "blockchain.scripthash.get_balance",
        &json!([sh_hex, tagged]),
        true,
    )
    .unwrap();
    assert!(h.is_some());
    assert_eq!(rest, json!([sh_hex]));
    let (rest_win, h_win) = take_trailing_asof(
        "blockchain.scripthash.get_history",
        &json!([sh_hex, 1, 10, tagged]),
        true,
    )
    .unwrap();
    assert!(h_win.is_some());
    assert_eq!(rest_win, json!([sh_hex, 1, 10]));
    let (rest_tx, h_tx) =
        take_trailing_asof("blockchain.transaction.get", &json!([sh_hex, tagged]), true).unwrap();
    assert!(h_tx.is_some());
    assert_eq!(rest_tx, json!([sh_hex]));
    let (rest_merkle, h_merkle) = take_trailing_asof(
        "blockchain.transaction.get_merkle",
        &json!([sh_hex, 0, tagged]),
        true,
    )
    .unwrap();
    assert!(h_merkle.is_some());
    assert_eq!(rest_merkle, json!([sh_hex, 0]));
    let (_, none) =
        take_trailing_asof("blockchain.scripthash.get_balance", &json!([sh_hex]), true).unwrap();
    assert!(none.is_none());
    let (_, not_hex) = take_trailing_asof(
        "blockchain.scripthash.get_balance",
        &json!([sh_hex, asof_hex]),
        true,
    )
    .unwrap();
    assert!(
        not_hex.is_none(),
        "bare trailing hex must not be asof (future positional hash args)"
    );
    let (_, leftover_obj) = take_trailing_asof(
        "blockchain.scripthash.get_balance",
        &json!([sh_hex, { "other": true }]),
        true,
    )
    .unwrap();
    assert!(leftover_obj.is_none());
    let denied = take_trailing_asof(
        "blockchain.scripthash.get_balance",
        &json!([sh_hex, tagged]),
        false,
    )
    .unwrap_err();
    assert!(
        denied.contains("1.4.2-asof"),
        "asof tag without dialect: {denied}"
    );
    assert!(take_trailing_asof(
        "blockchain.scripthash.get_balance",
        &json!([sh_hex, "asof:zz"]),
        true,
    )
    .unwrap_err()
    .contains("asof:<32-byte hex>"));
    let asof_tag = format!("asof:{}", "ab".repeat(32));
    let (_, ignored) =
        take_trailing_asof("blockchain.block.header", &json!([0, asof_tag]), true).unwrap();
    assert!(
        ignored.is_none(),
        "asof tag on a method that does not accept asof is leftover params, not a view"
    );
    assert!(parse_get_history_window(&json!({}))
        .unwrap_err()
        .contains("array"));

    assert!(parse_get_history_window(&json!([sh_hex, 10, 5]))
        .unwrap_err()
        .contains("from_height"));
    assert!(parse_get_history_window(&json!([sh_hex, 0, -2]))
        .unwrap_err()
        .contains("to_height"));

    let empty_status = scripthash_status(None, &[]).unwrap();
    assert!(empty_status.is_empty());
    let missing = scripthash_status(
        None,
        &[rbitcoin_query::ScriptHashHistoryItem {
            height: 1,
            txid: [1u8; 32],
            tx_fk: Fk::NULL,
            fee: None,
        }],
    )
    .unwrap_err();
    assert!(
        missing.contains("query"),
        "confirmed preimage without query: {missing}"
    );
    let (dir, q) = tmp_store();
    let missing_hdr = scripthash_status(
        Some(&q),
        &[rbitcoin_query::ScriptHashHistoryItem {
            height: 1,
            txid: [1u8; 32],
            tx_fk: Fk::NULL,
            fee: None,
        }],
    )
    .unwrap_err();
    assert!(
        missing_hdr.contains("header missing"),
        "confirmed row without header: {missing_hdr}"
    );
    let _ = std::fs::remove_dir_all(&dir);

    use bitcoin::hashes::Hash;
    let hdr = bitcoin::block::Header {
        version: bitcoin::block::Version::ONE,
        prev_blockhash: bitcoin::BlockHash::from_byte_array([0; 32]),
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([0; 32]),
        time: 0,
        bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
        nonce: 0,
    };
    let hex = header_hex(&hdr);
    assert_eq!(hex.len(), 160);

    assert_eq!(tick_scan(Some(1), Some(1)), None);
    assert_eq!(tick_scan(Some(0), Some(2)), Some(Some(vec![1, 2])));
    assert_eq!(tick_scan(Some(0), Some(32)), Some(Some((1..=32).collect())));
    assert_eq!(
        tick_scan(Some(0), Some(33)),
        Some(None),
        "gap above TICK_SCAN_MAX_GAP restatuses all"
    );
    assert_eq!(tick_scan(Some(2), Some(1)), Some(None));
    assert_eq!(tick_scan(None, Some(0)), Some(None));
    let mut last = HashMap::new();
    let mut subs = HashSet::new();
    let sh = [9u8; 32];
    subs.insert(sh);
    let first = take_new_status(&mut last, &subs, sh, "aa".into()).unwrap();
    assert_eq!(first, "aa");
    assert!(take_new_status(&mut last, &subs, sh, "aa".into()).is_none());
    assert_eq!(
        take_new_status(&mut last, &subs, sh, "bb".into()).unwrap(),
        "bb"
    );
}

#[test]
fn cached_confirming_hash_loads_once_per_height() {
    let mut cache = HashMap::new();
    let mut loads = 0u32;
    let mut load = |h: u32| {
        loads += 1;
        Ok::<_, String>([h as u8; 32])
    };
    let a = cached_confirming_hash(7, &mut cache, &mut load).unwrap();
    let b = cached_confirming_hash(7, &mut cache, &mut load).unwrap();
    let c = cached_confirming_hash(8, &mut cache, &mut load).unwrap();
    assert_eq!(a, [7u8; 32]);
    assert_eq!(b, [7u8; 32]);
    assert_eq!(c, [8u8; 32]);
    assert_eq!(loads, 2, "same height must not load twice");
}

/// A subscribe that answered `null` (no history) dedups a later push that is
/// still empty, and an empty status goes out as `null`, never `""`.
#[test]
fn null_status_is_recorded_and_deduplicated() {
    assert_eq!(status_json(String::new()), Value::Null);
    assert_eq!(status_json("ab".into()), json!("ab"));
    let sh = [7u8; 32];
    let subs: HashSet<[u8; 32]> = [sh].into_iter().collect();
    let mut last = HashMap::new();
    record_sent_status(&mut last, sh, &Value::Null);
    assert!(take_new_status(&mut last, &subs, sh, String::new()).is_none());
    assert_eq!(
        take_new_status(&mut last, &subs, sh, "cd".into()).as_deref(),
        Some("cd")
    );
    record_sent_status(&mut last, sh, &json!("ef"));
    assert!(take_new_status(&mut last, &subs, sh, "ef".into()).is_none());
    assert_eq!(
        take_new_status(&mut last, &subs, sh, String::new()).as_deref(),
        Some("")
    );
}

/// The block/reorg restatus push sends `null` when a watched script's status
/// was last sent non-empty and its history is now empty, once: the next pass
/// is deduplicated.
#[tokio::test]
async fn block_restatus_pushes_null_for_emptied_history() {
    let (_dir, q) = tmp_store();
    let q = Arc::new(q);
    let sh = script_hash(&[0x51]);
    let subs: HashSet<[u8; 32]> = [sh].into_iter().collect();
    let mut last = HashMap::from([(sh, "aa".to_string())]);
    let mut out = Vec::new();
    emit_sh_notes(&mut out, &q, None, &subs, &mut last, None)
        .await
        .unwrap();
    let lines: Vec<Value> = std::str::from_utf8(&out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["method"], "blockchain.scripthash.subscribe");
    assert_eq!(lines[0]["params"][0], json!(hash_hex_rev(&sh)));
    assert_eq!(lines[0]["params"][1], Value::Null, "{lines:?}");
    let mut again = Vec::new();
    emit_sh_notes(&mut again, &q, None, &subs, &mut last, None)
        .await
        .unwrap();
    assert!(again.is_empty(), "still empty: no second push");
}

#[test]
fn drop_unsubscribed_status_clears_idle_hashes() {
    let mut last = HashMap::new();
    let gone = [1u8; 32];
    let keep = [2u8; 32];
    last.insert(gone, "x".into());
    last.insert(keep, "y".into());
    let mut subs = HashSet::new();
    subs.insert(keep);
    drop_unsubscribed_status(&mut last, &subs);
    assert_eq!(last.get(&keep), Some(&"y".to_string()));
    assert!(!last.contains_key(&gone));
}

#[test]
fn restatus_notes_scans_intermediate_tick_heights() {
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

    let (dir, q) = tmp_store();
    let merkle = [0x51; 32];
    let h0 = HeaderRecord {
        prev_fk: Fk::NULL,
        version: 1,
        timestamp: 1,
        bits: 0x207fffff,
        nonce: 0,
        merkle_root: merkle,
        hash: merkle,
        size: 0,
        weight: 0,
    };
    let mut txid0 = [0u8; 32];
    txid0[0] = 0xa0;
    let ta0 = TxApply {
        tx: TxRecord {
            txid: txid0,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: [0u8; 32],
            create_fk: Fk::NULL,
            prev_index: u32::MAX,
            sequence: u32::MAX,
            script_sig: vec![0],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
    };
    let hfk0 = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
    let hash1 = rbitcoin_store::block_header_hash(1, &merkle, &[0x11; 32], 2, 0x207fffff, 1);
    let h1 = HeaderRecord {
        prev_fk: hfk0,
        version: 1,
        timestamp: 2,
        bits: 0x207fffff,
        nonce: 1,
        merkle_root: [0x11; 32],
        hash: hash1,
        size: 0,
        weight: 0,
    };
    let mut txid1 = [0u8; 32];
    txid1[0] = 0xa1;
    q.connect_block(
        Height(1),
        &h1,
        &[TxApply {
            tx: TxRecord {
                txid: txid1,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk::NULL,
                prev_index: u32::MAX,
                sequence: u32::MAX,
                script_sig: vec![1],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x00])],
        }],
    )
    .unwrap();
    q.apply_sh_pending().unwrap();
    let sh = rbitcoin_store::script_hash(&[0x51]);
    let only_tip = restatus_notes(&q, None, &[sh], Some(&[1]));
    assert!(
        only_tip.is_empty(),
        "height 1 does not touch the OP_TRUE script"
    );
    let range = restatus_notes(&q, None, &[sh], Some(&[1, 0]));
    assert_eq!(range.len(), 1, "range must include the height-0 create");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn negotiate_protocol_intersection_and_asof_dialect() {
    assert_eq!(negotiate_protocol(&json!([])).unwrap(), PROTOCOL_MAX);
    assert_eq!(negotiate_protocol(&json!(["c"])).unwrap(), PROTOCOL_MAX);
    assert_eq!(negotiate_protocol(&json!(["c", "1.4"])).unwrap(), "1.4");
    assert_eq!(negotiate_protocol(&json!(["c", "1.4.2"])).unwrap(), "1.4.2");
    assert_eq!(
        negotiate_protocol(&json!(["c", ["1.4", "1.4.2"]])).unwrap(),
        "1.4.2"
    );
    assert_eq!(
        negotiate_protocol(&json!(["c", PROTOCOL_ASOF])).unwrap(),
        PROTOCOL_ASOF
    );
    assert_eq!(
        negotiate_protocol(&json!(["c", ["1.4", PROTOCOL_ASOF]])).unwrap(),
        PROTOCOL_ASOF
    );
    assert_eq!(negotiate_protocol(&json!(["c", "1.6"])).unwrap(), "1.6");
    assert!(negotiate_protocol(&json!(["c", "1.7"]))
        .unwrap_err()
        .contains("unsupported"));
    assert!(negotiate_protocol(&json!(["c", ["1.6.1", "1.7"]]))
        .unwrap_err()
        .contains("unsupported"));
}

async fn electrum_tcp_rpc(stream: &mut TcpStream, id: u32, method: &str, params: Value) -> Value {
    let req = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    stream.write_all(line.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(&mut *stream);
    let mut resp = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        reader.read_line(&mut resp),
    )
    .await
    .expect("timeout")
    .unwrap();
    serde_json::from_str(&resp).unwrap()
}

#[allow(clippy::cognitive_complexity)] // one TCP client, static methods + no-hub fees
#[tokio::test]
async fn accept_client_ping_and_shutdown() {
    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let q = std::sync::Arc::new(q);
    let (tip_tx, _) = broadcast::channel(4);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let banner = cfg.banner.clone();
    let handle = run_electrum(cfg, q, params, tip_tx, None)
        .await
        .expect("listen");

    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
    let v = electrum_tcp_rpc(&mut stream, 1, "server.ping", json!([])).await;
    assert_eq!(v["id"], 1);
    assert!(v.get("result").is_some());
    assert!(
        v.get("chain_tip").is_none(),
        "ping must not grow chain_tip: {v}"
    );

    stream.write_all(b"\n").await.unwrap();
    stream.write_all(b"{not json\n").await.unwrap();
    let v = electrum_tcp_rpc(&mut stream, 2, "server.version", json!([])).await;
    assert_eq!(v["id"], 2);
    let ver = v["result"].as_array().expect("version array");
    assert_eq!(ver.len(), 2);
    let cake_server = ver[0].as_str().expect("server.version[0] string");
    assert!(
        cake_server.to_ascii_lowercase().contains("electrs"),
        "Cake skips tweaks unless version[0] contains electrs, got {cake_server:?}"
    );
    assert!(
        cake_server.to_ascii_lowercase().contains("rbitcoin"),
        "version[0] must still identify rbitcoin, got {cake_server:?}"
    );
    assert!(
        cake_server.contains(env!("CARGO_PKG_VERSION")),
        "version[0] must track workspace.package.version, got {cake_server:?}"
    );
    assert_eq!(ver[1], PROTOCOL_MAX);

    let features = electrum_tcp_rpc(&mut stream, 3, "server.features", json!([])).await;
    let features = &features["result"];
    assert_eq!(features["protocol_min"], PROTOCOL_MIN);
    assert_eq!(features["protocol_max"], PROTOCOL_MAX);
    assert_eq!(features["server_version"], ver[0]);
    assert_eq!(features["silent_payments"], json!([0]));
    assert_eq!(features["tweaks"], json!(true));
    assert_eq!(features["chain_tip"], json!(true));
    assert_eq!(features["asof"], json!(true));
    assert_eq!(features["asof_protocol"], PROTOCOL_ASOF);
    assert_eq!(features["hosts"], json!({}));

    let probe = electrum_tcp_rpc(
        &mut stream,
        4,
        "blockchain.tweaks.subscribe",
        json!([0, 1, false]),
    )
    .await;
    assert_eq!(probe["result"], json!({"0": {}}));

    let banner_v = electrum_tcp_rpc(&mut stream, 5, "server.banner", json!([])).await;
    assert_eq!(banner_v["result"].as_str().unwrap(), banner);

    let don = electrum_tcp_rpc(&mut stream, 6, "server.donation_address", json!([])).await;
    assert!(don["result"].as_str().is_some());

    let peers = electrum_tcp_rpc(&mut stream, 7, "server.peers.subscribe", json!([])).await;
    assert_eq!(peers["result"], json!([]));

    let fee = electrum_tcp_rpc(&mut stream, 8, "blockchain.relayfee", json!([])).await;
    assert!(fee["result"].as_f64().is_some());

    let est = electrum_tcp_rpc(&mut stream, 9, "blockchain.estimatefee", json!([6])).await;
    assert_eq!(est["result"].as_f64(), Some(-1.0));

    let hist = electrum_tcp_rpc(&mut stream, 10, "mempool.get_fee_histogram", json!([])).await;
    assert_eq!(hist["result"], json!([]));

    let unk = electrum_tcp_rpc(&mut stream, 11, "no.such.method", json!([])).await;
    assert!(
        unk["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("unknown method")
            || unk["error"]
                .as_str()
                .unwrap_or("")
                .contains("unknown method"),
        "{unk}"
    );

    let bad = electrum_tcp_rpc(
        &mut stream,
        12,
        "blockchain.transaction.broadcast",
        json!(["zz"]),
    )
    .await;
    assert!(bad.get("error").is_some(), "{bad}");
    let bad_hex = electrum_tcp_rpc(
        &mut stream,
        13,
        "blockchain.transaction.broadcast",
        json!(["01000000000000000000"]),
    )
    .await;
    assert!(bad_hex.get("error").is_some(), "{bad_hex}");

    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// On a 1-worker runtime, ping must complete while another socket is inside
/// a real blocking store query (`blockchain.block.headers`).
#[tokio::test(flavor = "current_thread")]
async fn ping_overlaps_blocking_headers_on_one_worker() {
    use rbitcoin_consensus::{accept_and_connect_block, Milestone};
    use rbitcoin_primitives::Height;
    use std::sync::atomic::AtomicU64;

    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    // Enough headers that a serial walk stays in-flight after ping is scheduled.
    let _ = rbitcoin_consensus::pad_empty_from(
        &q,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        80,
        0,
    );
    let q = Arc::new(q);
    let (tip_tx, _) = broadcast::channel(4);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let handle = run_electrum(cfg, q, params, tip_tx, None)
        .await
        .expect("listen");
    let addr = handle.local_addr;

    let mut a = TcpStream::connect(addr).await.unwrap();
    let mut b = TcpStream::connect(addr).await.unwrap();
    let a_started = Arc::new(AtomicBool::new(false));
    let a_done_us = Arc::new(AtomicU64::new(0));
    let b_done_us = Arc::new(AtomicU64::new(0));
    let t0 = Instant::now();

    let a_started_c = Arc::clone(&a_started);
    let a_done_c = Arc::clone(&a_done_us);
    let ha = tokio::spawn(async move {
        let req = json!({
            "jsonrpc":"2.0","id":10,
            "method":"blockchain.block.headers","params":[0, 2016]
        });
        let mut line = serde_json::to_string(&req).unwrap();
        line.push('\n');
        a.write_all(line.as_bytes()).await.unwrap();
        a_started_c.store(true, Ordering::SeqCst);
        let mut reader = BufReader::new(a);
        let mut resp = String::new();
        reader.read_line(&mut resp).await.unwrap();
        a_done_c.store(t0.elapsed().as_micros() as u64, Ordering::SeqCst);
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["id"], 10);
        assert!(v["result"]["count"].as_u64().unwrap() > 50);
    });

    let a_started_c = Arc::clone(&a_started);
    let b_done_c = Arc::clone(&b_done_us);
    let hb = tokio::spawn(async move {
        while !a_started_c.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        let req = json!({"jsonrpc":"2.0","id":11,"method":"server.ping","params":[]});
        let mut line = serde_json::to_string(&req).unwrap();
        line.push('\n');
        b.write_all(line.as_bytes()).await.unwrap();
        let mut reader = BufReader::new(b);
        let mut resp = String::new();
        reader.read_line(&mut resp).await.unwrap();
        b_done_c.store(t0.elapsed().as_micros() as u64, Ordering::SeqCst);
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["id"], 11);
        assert!(v.get("result").is_some());
    });

    ha.await.expect("headers task");
    hb.await.expect("ping task");
    let a_done = a_done_us.load(Ordering::SeqCst);
    let b_done = b_done_us.load(Ordering::SeqCst);
    assert!(
        b_done < a_done,
        "ping finished at {b_done}µs, headers at {a_done}µs (expected overlap)"
    );

    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn api_log_records_electrum_method() {
    let (dir, q) = tmp_store();
    let log_path = dir.join("api.jsonl");
    rbitcoin_log::init_api_log(&log_path).unwrap();
    let params = ChainParams::regtest();
    let q = std::sync::Arc::new(q);
    let (tip_tx, _) = broadcast::channel(4);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let handle = run_electrum(cfg, q, params, tip_tx, None)
        .await
        .expect("listen");

    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
    let req = json!({"jsonrpc":"2.0","id":1,"method":"server.ping","params":[]});
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    stream.write_all(line.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(&mut stream);
    let mut resp = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        reader.read_line(&mut resp),
    )
    .await
    .expect("timeout")
    .unwrap();
    handle.shutdown().await;
    rbitcoin_log::close_api_log();
    let body = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        body.contains("\"method\":\"server.ping\""),
        "api log missing ping: {body}"
    );
    assert!(body.contains("\"surface\":\"electrum\""));
    let _ = std::fs::remove_dir_all(&dir);
}

/// BCH-style optional `from_height`/`to_height` on get_history; status stays full.
#[test]
fn get_history_height_window_and_status_full() {
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

    let (dir, q) = tmp_store();
    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    for h in 0..4u32 {
        let version = 1;
        let timestamp = h + 1;
        let bits = 0x207fffff;
        let nonce = h;
        let mut merkle = [0u8; 32];
        merkle[0..4].copy_from_slice(&h.to_le_bytes());
        merkle[5] = 0xee;
        let hash = match parent_hash {
            None => merkle,
            Some(ph) => {
                rbitcoin_store::block_header_hash(version, &ph, &merkle, timestamp, bits, nonce)
            }
        };
        let header = HeaderRecord {
            prev_fk: prev,
            version,
            timestamp,
            bits,
            nonce,
            merkle_root: merkle,
            hash,
            size: 0,
            weight: 0,
        };
        let mut txid = [0u8; 32];
        txid[0..4].copy_from_slice(&h.to_le_bytes());
        txid[31] = 0xcb;
        let ta = TxApply {
            tx: TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk::NULL,
                prev_index: u32::MAX,
                sequence: u32::MAX,
                script_sig: vec![h as u8],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
        };
        parent_hash = Some(header.hash);
        prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
    }

    let params = ChainParams::regtest();
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let mut header_sub = false;
    let mut sh_subs = HashSet::new();
    let sh = electrum_scripthash_hex(&[0x51]);

    let full = dispatch(
        "blockchain.scripthash.get_history",
        &json!([sh]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    let full_arr = full.as_array().unwrap();
    assert_eq!(full_arr.len(), 4);

    // Inclusive from, exclusive to → heights 1 and 2 only.
    let windowed = dispatch(
        "blockchain.scripthash.get_history",
        &json!([sh, 1, 3]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    let w = windowed.as_array().unwrap();
    assert_eq!(w.len(), 2);
    assert_eq!(w[0]["height"], 1);
    assert_eq!(w[1]["height"], 2);
    assert!(w.len() < full_arr.len());

    // to_height=-1 is open upper (same as full for confirmed-only).
    let open_to = dispatch(
        "blockchain.scripthash.get_history",
        &json!([sh, 0, -1]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert_eq!(open_to.as_array().unwrap().len(), full_arr.len());

    // Subscribe status is always full history, independent of windowed calls.
    let status = dispatch(
        "blockchain.scripthash.subscribe",
        &json!([sh]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    let status_s = status.as_str().unwrap();
    assert!(!status_s.is_empty());
    // Recompute status from full confirmed history and match.
    let sh_bytes = {
        let mut b = rbitcoin_primitives::hex_decode(&sh).unwrap();
        b.reverse();
        let mut out = [0u8; 32];
        out.copy_from_slice(&b);
        out
    };
    let full_hist = q.scripthash_history(&sh_bytes).unwrap();
    assert_eq!(full_hist.len(), 4);
    assert_eq!(scripthash_status(Some(&q), &full_hist).unwrap(), status_s);

    let _ = prev;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn chain_view_reorg_notifies_dropped_scripthash() {
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

    let (dir, q) = tmp_store();
    let mut hash = [0u8; 32];
    hash[0] = 0x42;
    let header = HeaderRecord {
        prev_fk: Fk::NULL,
        version: 1,
        timestamp: 1,
        bits: 0x207fffff,
        nonce: 0,
        merkle_root: hash,
        hash,
        size: 0,
        weight: 0,
    };
    let mut txid = [0u8; 32];
    txid[31] = 0xcb;
    let ta = TxApply {
        tx: TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: [0u8; 32],
            create_fk: Fk::NULL,
            prev_index: u32::MAX,
            sequence: u32::MAX,
            script_sig: vec![0],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(1, vec![0x51])],
    };
    let hfk0 = q.connect_block(Height(0), &header, &[ta]).unwrap();
    let sh = electrum_scripthash_hex(&[0x51]);

    let params = ChainParams::regtest();
    let q = std::sync::Arc::new(q);
    let (tip_tx, _) = broadcast::channel(2);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let handle = run_electrum(cfg, std::sync::Arc::clone(&q), params, tip_tx.clone(), None)
        .await
        .unwrap();
    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
    let mut line = serde_json::to_string(&json!({
        "jsonrpc":"2.0","id":1,"method":"blockchain.scripthash.subscribe","params":[sh]
    }))
    .unwrap();
    line.push('\n');
    stream.write_all(line.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(&mut stream);
    let mut resp = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        reader.read_line(&mut resp),
    )
    .await
    .unwrap()
    .unwrap();
    let first: Value = serde_json::from_str(&resp).unwrap();
    let status0 = first["result"].as_str().unwrap().to_string();
    assert!(!status0.is_empty());
    let _ = hfk0;
    // A never-used script answers null, and that null is remembered: the
    // reorg below restatuses every sub, and this one must not be pushed.
    let fresh = electrum_scripthash_hex(&[0x52]);
    let mut line = serde_json::to_string(&json!({
        "jsonrpc":"2.0","id":2,"method":"blockchain.scripthash.subscribe","params":[fresh]
    }))
    .unwrap();
    line.push('\n');
    reader.get_mut().write_all(line.as_bytes()).await.unwrap();
    resp.clear();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        reader.read_line(&mut resp),
    )
    .await
    .unwrap()
    .unwrap();
    let fresh_reply: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(fresh_reply["id"], 2, "{fresh_reply}");
    assert_eq!(fresh_reply["result"], Value::Null, "{fresh_reply}");

    q.disconnect_tip().unwrap();
    let mut hash_b = [0u8; 32];
    hash_b[0] = 0x43;
    let header_b = HeaderRecord {
        prev_fk: Fk::NULL,
        version: 1,
        timestamp: 1,
        bits: 0x207fffff,
        nonce: 1,
        merkle_root: hash_b,
        hash: hash_b,
        size: 0,
        weight: 0,
    };
    let mut txid_b = [0u8; 32];
    txid_b[0] = 0x99;
    txid_b[31] = 0xcd;
    let ta_b = TxApply {
        tx: TxRecord {
            txid: txid_b,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: [0u8; 32],
            create_fk: Fk::NULL,
            prev_index: u32::MAX,
            sequence: u32::MAX,
            script_sig: vec![1],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(1, vec![0x00])],
    };
    q.connect_block(Height(0), &header_b, &[ta_b]).unwrap();
    tip_tx
        .send(TipNotify {
            height: 0,
            header_hex: "aa".repeat(80),
            reorg_from_height: Some(0),
        })
        .unwrap();
    resp.clear();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        reader.read_line(&mut resp),
    )
    .await
    .expect("reorg must restatus even when the new block misses the scripthash")
    .unwrap();
    let push: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        push["method"].as_str(),
        Some("blockchain.scripthash.subscribe")
    );
    assert_eq!(push["params"][0], json!(sh), "{push}");
    assert_eq!(
        push["params"][1],
        Value::Null,
        "the reorg dropped the script's only tx, so its status is null: {push}"
    );
    // The connection is serial: a redundant push for the fresh script would
    // arrive before this ping's reply.
    let mut line = serde_json::to_string(&json!({
        "jsonrpc":"2.0","id":3,"method":"server.ping","params":[]
    }))
    .unwrap();
    line.push('\n');
    reader.get_mut().write_all(line.as_bytes()).await.unwrap();
    resp.clear();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        reader.read_line(&mut resp),
    )
    .await
    .unwrap()
    .unwrap();
    let next: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        next["id"], 3,
        "no push for the still-empty fresh script: {next}"
    );

    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// DoS: line without newline beyond max must fail without allocating forever.
#[tokio::test]
async fn read_line_capped_rejects_oversize() {
    use std::io::Cursor;
    use tokio::io::BufReader;
    let mut r = BufReader::new(Cursor::new(vec![b'A'; 64]));
    let err = read_line_capped(&mut r, 32).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn read_line_capped_accepts_under_limit() {
    use std::io::Cursor;
    use tokio::io::BufReader;
    let mut r = BufReader::new(Cursor::new(b"{\"id\":1}\nnext\n".as_slice()));
    let line = read_line_capped(&mut r, 1024).await.unwrap().unwrap();
    assert_eq!(line, "{\"id\":1}");
    let line2 = read_line_capped(&mut r, 1024).await.unwrap().unwrap();
    assert_eq!(line2, "next");
}

#[test]
fn broadcast_hex_cap_enforced() {
    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    cfg.max_broadcast_hex = 16;
    let mut header_sub = false;
    let mut sh_subs = HashSet::new();
    let err = dispatch(
        "blockchain.transaction.broadcast",
        &json!(["aa".repeat(20)]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap_err();
    assert!(err.contains("too large"), "{err}");
    let pkg_err = dispatch(
        "blockchain.transaction.broadcast_package",
        &json!([["aa".repeat(20)]]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap_err();
    assert!(pkg_err.contains("too large"), "{pkg_err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn serve_limits_public_proxy_defaults() {
    let lim = ServeLimits::for_public_proxy();
    assert_eq!(lim.max_connections, DEFAULT_MAX_CONNECTIONS);
    assert_eq!(lim.max_request_bytes, DEFAULT_MAX_REQUEST_BYTES);
    assert_eq!(
        lim.idle_timeout,
        Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS)
    );
    let params = ChainParams::regtest();
    let cfg = ElectrumConfig::for_params("0.0.0.0:50001".parse().unwrap(), &params);
    assert_eq!(cfg.limits, lim);
    assert_eq!(cfg.max_connections(), DEFAULT_MAX_CONNECTIONS);
    assert_eq!(cfg.max_line_bytes(), DEFAULT_MAX_LINE_BYTES);
}

#[tokio::test]
async fn tweaks_subscribe_zero_chunk_dones_after_wave0_then_resubscribe() {
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

    let (dir, q) = tmp_store();
    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    for h in 0..5u32 {
        let mut merkle = [0u8; 32];
        merkle[0..4].copy_from_slice(&h.to_le_bytes());
        merkle[5] = 0xec;
        let hash = match parent_hash {
            None => merkle,
            Some(ph) => rbitcoin_store::block_header_hash(1, &ph, &merkle, h + 1, 0x207fffff, h),
        };
        let header = HeaderRecord {
            prev_fk: prev,
            version: 1,
            timestamp: h + 1,
            bits: 0x207fffff,
            nonce: h,
            merkle_root: merkle,
            hash,
            size: 0,
            weight: 0,
        };
        let mut txid = [0u8; 32];
        txid[0..4].copy_from_slice(&h.to_le_bytes());
        txid[31] = 0xcb;
        let ta = TxApply {
            tx: TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord::coinbase(u32::MAX, vec![h as u8], vec![])],
            outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
        };
        prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        parent_hash = Some(hash);
    }

    let params = ChainParams::regtest();
    let q = std::sync::Arc::new(q);
    let (tip_tx, _) = broadcast::channel(4);
    let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    cfg.tweaks_chunk = Duration::ZERO;
    let handle = run_electrum(cfg, q, params, tip_tx, None)
        .await
        .expect("listen");

    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
    async fn read_json(reader: &mut BufReader<&mut TcpStream>) -> Value {
        let mut resp = String::new();
        tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut resp))
            .await
            .unwrap_or_else(|_| panic!("tweaks stream: timed out"))
            .unwrap();
        serde_json::from_str(&resp).unwrap_or_else(|e| panic!("tweaks stream parse {e}: {resp}"))
    }
    async fn subscribe(stream: &mut TcpStream, id: &str, start: u32, count: u32) {
        let req = json!({
            "jsonrpc":"2.0","id": id,
            "method":"blockchain.tweaks.subscribe",
            "params":[start, count, false]
        });
        let mut line = serde_json::to_string(&req).unwrap();
        line.push('\n');
        stream.write_all(line.as_bytes()).await.unwrap();
    }

    subscribe(&mut stream, "scan", 1, 3).await;
    let mut reader = BufReader::new(&mut stream);

    let result = read_json(&mut reader).await;
    assert_eq!(result["id"], "scan");
    let map = result["result"].as_object().expect("result map");
    assert_eq!(map.len(), 1, "wave 0 result is one height, got {map:?}");
    assert!(map.contains_key("1"), "{map:?}");

    let done = read_json(&mut reader).await;
    assert_eq!(done["method"], "blockchain.tweaks.subscribe");
    assert_eq!(
        done["params"][0]["message"], "done",
        "zero chunk must done after wave 0 with heights left, got {done}"
    );

    drop(reader);
    subscribe(&mut stream, "scan2", 2, 2).await;
    let mut reader = BufReader::new(&mut stream);
    let result2 = read_json(&mut reader).await;
    assert_eq!(result2["id"], "scan2");
    let map2 = result2["result"].as_object().expect("resubscribe result");
    assert!(
        map2.contains_key("2"),
        "Cake noData path resubscribes on the same socket, got {map2:?}"
    );

    let done2 = read_json(&mut reader).await;
    assert_eq!(done2["params"][0]["message"], "done");

    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn tweaks_subscribe_pre_taproot_collapses_empty_heights() {
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

    let (dir, q) = tmp_store();
    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    for h in 0..5u32 {
        let mut merkle = [0u8; 32];
        merkle[0..4].copy_from_slice(&h.to_le_bytes());
        merkle[5] = 0xec;
        let hash = match parent_hash {
            None => merkle,
            Some(ph) => rbitcoin_store::block_header_hash(1, &ph, &merkle, h + 1, 0x207fffff, h),
        };
        let header = HeaderRecord {
            prev_fk: prev,
            version: 1,
            timestamp: h + 1,
            bits: 0x207fffff,
            nonce: h,
            merkle_root: merkle,
            hash,
            size: 0,
            weight: 0,
        };
        let mut txid = [0u8; 32];
        txid[0..4].copy_from_slice(&h.to_le_bytes());
        txid[31] = 0xcb;
        let ta = TxApply {
            tx: TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord::coinbase(u32::MAX, vec![h as u8], vec![])],
            outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
        };
        prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        parent_hash = Some(hash);
    }

    let params = ChainParams::mainnet();
    let q = std::sync::Arc::new(q);
    let (tip_tx, _) = broadcast::channel(4);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let handle = run_electrum(cfg, q, params, tip_tx, None)
        .await
        .expect("listen");

    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
    let req = json!({
        "jsonrpc":"2.0","id":"scan",
        "method":"blockchain.tweaks.subscribe",
        "params":[0, 5, false]
    });
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    stream.write_all(line.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(&mut stream);

    async fn read_json(reader: &mut BufReader<&mut TcpStream>) -> Value {
        let mut resp = String::new();
        tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut resp))
            .await
            .unwrap_or_else(|_| panic!("tweaks stream: timed out"))
            .unwrap();
        serde_json::from_str(&resp).unwrap_or_else(|e| panic!("tweaks stream parse {e}: {resp}"))
    }

    let result = read_json(&mut reader).await;
    assert_eq!(result["id"], "scan");
    let map = result["result"].as_object().expect("result map");
    assert_eq!(map.len(), 1, "probe/result stays one height, got {map:?}");
    assert!(map.contains_key("0"), "{map:?}");

    let n = read_json(&mut reader).await;
    assert_eq!(n["method"], "blockchain.tweaks.subscribe");
    let p = n["params"][0].as_object().expect("collapsed notify");
    assert_eq!(p.len(), 4, "heights 1..=4 in one notify, got {p:?}");
    for h in 1u32..=4 {
        assert!(p.contains_key(&h.to_string()), "{p:?}");
        assert!(p[&h.to_string()].as_object().unwrap().is_empty());
    }

    let done = read_json(&mut reader).await;
    assert_eq!(done["method"], "blockchain.tweaks.subscribe");
    assert_eq!(done["params"][0]["message"], "done");

    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[allow(clippy::cognitive_complexity)] // one store, every method's missing/wrong-type params
#[test]
fn dispatch_param_type_edges_and_subscribe_cap() {
    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    cfg.max_scripthash_subs = 1;
    let mut header_sub = false;
    let mut sh_subs = HashSet::new();
    let sh = electrum_scripthash_hex(&[0x51]);
    let sh2 = electrum_scripthash_hex(&[0x52]);

    for (method, args, needle) in [
        ("blockchain.block.header", json!([]), "expected number"),
        ("blockchain.block.header", json!([true]), "expected number"),
        ("blockchain.block.headers", json!([]), "expected number"),
        (
            "blockchain.scripthash.get_history",
            json!([]),
            "expected string",
        ),
        (
            "blockchain.scripthash.get_history",
            json!([1]),
            "expected string",
        ),
        (
            "blockchain.scripthash.get_balance",
            json!(["aa"]),
            "scripthash must be 32 bytes hex",
        ),
        (
            "blockchain.scripthash.listunspent",
            json!([true]),
            "expected string",
        ),
        (
            "blockchain.scripthash.subscribe",
            json!([]),
            "expected string",
        ),
        (
            "blockchain.scripthash.unsubscribe",
            json!(["zz".repeat(32)]),
            "invalid hex",
        ),
        (
            "blockchain.scripthash.get_mempool",
            json!({}),
            "expected string",
        ),
        (
            "blockchain.transaction.get",
            json!(["aabb"]),
            "txid must be 32 bytes hex",
        ),
        (
            "blockchain.transaction.get_merkle",
            json!([sh]),
            "expected number",
        ),
        (
            "blockchain.transaction.broadcast",
            json!([]),
            "expected string",
        ),
        (
            "blockchain.transaction.broadcast",
            json!([1]),
            "expected string",
        ),
        (
            "blockchain.transaction.broadcast_package",
            json!([]),
            "expected array of hex txs",
        ),
        (
            "blockchain.transaction.broadcast_package",
            json!([1]),
            "expected array of hex txs",
        ),
        (
            "blockchain.transaction.broadcast_package",
            json!([[1]]),
            "tx must be hex",
        ),
        (
            "blockchain.transaction.broadcast_package",
            json!([["zz"]]),
            "invalid hex digit",
        ),
        (
            "blockchain.transaction.broadcast_package",
            json!([["00"]]),
            "IO error",
        ),
        (
            "blockchain.outpoint.get_status",
            json!([]),
            "expected string",
        ),
        (
            "blockchain.outpoint.subscribe",
            json!([sh]),
            "param 1 expected number",
        ),
        (
            "blockchain.outpoint.unsubscribe",
            json!([true, 0]),
            "expected string",
        ),
        (
            "blockchain.silentpayments.subscribe",
            json!([]),
            "expected string",
        ),
        (
            "blockchain.silentpayments.unsubscribe",
            json!([1, 2]),
            "expected string",
        ),
        (
            "blockchain.transaction.id_from_pos",
            json!([]),
            "expected number",
        ),
        ("no.such.method", json!([]), "unknown method"),
    ] {
        let err = dispatch(
            method,
            &args,
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap_err();
        assert!(
            err.contains(needle),
            "{method} {args}: expected {needle:?} in {err}"
        );
    }

    let asof = format!("asof:{}", "ab".repeat(32));
    let err = dispatch(
        "blockchain.scripthash.get_balance",
        &json!([sh, asof]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap_err();
    assert!(err.contains("1.4.2-asof"), "asof without dialect: {err}");

    dispatch(
        "blockchain.scripthash.subscribe",
        &json!([sh]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    let err = dispatch(
        "blockchain.scripthash.subscribe",
        &json!([sh2]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap_err();
    assert!(err.contains("too many scripthash"), "{err}");
    let again = dispatch(
        "blockchain.scripthash.subscribe",
        &json!([sh]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert_eq!(again, Value::Null, "empty store: no history, null status");
    let dropped = dispatch(
        "blockchain.scripthash.unsubscribe",
        &json!([sh]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert_eq!(dropped, json!(true));
    let missing = dispatch(
        "blockchain.scripthash.unsubscribe",
        &json!([sh]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert_eq!(missing, json!(false));
    dispatch(
        "blockchain.scripthash.subscribe",
        &json!([sh2]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sp_scan_ranges_cover_one_height_and_the_next_chunk() {
    // A span past one chunk must fail a broken stop before a one-height call can spin.
    assert_eq!(
        super::sp_scan_ranges(0, crate::silent_scan::SP_SCAN_CHUNK),
        vec![
            (0, crate::silent_scan::SP_SCAN_CHUNK - 1),
            (
                crate::silent_scan::SP_SCAN_CHUNK,
                crate::silent_scan::SP_SCAN_CHUNK
            )
        ]
    );
    assert!(
        super::sp_scan_ranges(5, 4).is_empty(),
        "a start past the tip scans nothing"
    );
    assert_eq!(super::sp_scan_ranges(4, 4), vec![(4, 4)]);
    assert_eq!(super::sp_scan_ranges(0, 1), vec![(0, 1)]);
}

include!("electrum_sh_journey.rs");
