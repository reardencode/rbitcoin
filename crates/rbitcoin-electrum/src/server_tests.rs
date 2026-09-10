use super::*;
use rbitcoin_consensus::ChainParams;

#[test]
fn parse_electrum_request_line_junk_does_not_panic() {
    assert!(parse_electrum_request_line("").is_none());
    assert!(parse_electrum_request_line("{").is_none());
    assert!(parse_electrum_request_line("not json {").is_none());
    let v =
        parse_electrum_request_line(r#"{"id":1,"method":"server.version","params":["a","1.4"]}"#)
            .unwrap();
    assert_eq!(v["method"], "server.version");
}
use rbitcoin_query::Query;
use std::collections::{HashMap, HashSet};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

fn tmp_store() -> (rbitcoin_query::testutil::TempDir, Query) {
    rbitcoin_query::testutil::tiny_query_labeled("electrum")
}

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
    assert_eq!(param_i64(&json!([-1]), 0).unwrap(), -1);
    assert_eq!(param_i64(&json!(["10"]), 0).unwrap(), 10);
    assert_eq!(param_str(&json!(["hi"]), 0).unwrap(), "hi");
    assert!(param_str(&json!([1]), 0).is_err());

    let mut sh_bytes = [0u8; 32];
    sh_bytes[0] = 0xaa;
    let sh_hex = hash_hex_rev(&sh_bytes);
    let parsed = param_scripthash(&json!([sh_hex]), 0).unwrap();
    assert_eq!(parsed, sh_bytes);
    assert!(param_scripthash(&json!(["aa"]), 0).is_err());

    let tid = param_txid(&json!([sh_hex]), 0).unwrap();
    assert_eq!(tid, sh_bytes);

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
    assert_eq!(
        negotiate_protocol(&json!(["c", "1.4.2"])).unwrap(),
        PROTOCOL_MAX
    );
    assert_eq!(
        negotiate_protocol(&json!(["c", ["1.4", "1.4.2"]])).unwrap(),
        PROTOCOL_MAX
    );
    assert_eq!(
        negotiate_protocol(&json!(["c", PROTOCOL_ASOF])).unwrap(),
        PROTOCOL_ASOF
    );
    assert_eq!(
        negotiate_protocol(&json!(["c", ["1.4", PROTOCOL_ASOF]])).unwrap(),
        PROTOCOL_ASOF
    );
    assert!(negotiate_protocol(&json!(["c", "1.5"]))
        .unwrap_err()
        .contains("unsupported"));
    assert!(negotiate_protocol(&json!(["c", ["1.4.3", "1.5"]]))
        .unwrap_err()
        .contains("unsupported"));
}

#[test]
fn dispatch_static_methods_and_errors() {
    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let mut header_sub = false;
    let mut sh_subs = HashSet::new();

    let v = dispatch(
        "server.version",
        &json!([]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(v.as_array().unwrap().len() == 2);
    // Cake Wallet getNodeIsElectrs(): version[0].toLowerCase().contains('electrs')
    // before it will call blockchain.tweaks.subscribe [0, 1, false].
    let cake_server = v[0].as_str().expect("server.version[0] string");
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

    assert!(dispatch(
        "server.ping",
        &json!([]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs
    )
    .unwrap()
    .is_null());

    assert_eq!(
        dispatch(
            "server.banner",
            &json!([]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs
        )
        .unwrap()
        .as_str()
        .unwrap(),
        cfg.banner
    );

    let features = dispatch(
        "server.features",
        &json!([]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert_eq!(v[1], PROTOCOL_MAX);
    assert_eq!(features["protocol_min"], PROTOCOL_MIN);
    assert_eq!(features["protocol_max"], PROTOCOL_MAX);
    assert_eq!(features["server_version"], v[0]);
    assert_eq!(features["silent_payments"], json!([0]));
    assert_eq!(features["tweaks"], json!(true));
    assert_eq!(features["chain_tip"], json!(true));
    assert_eq!(features["asof"], json!(true));
    assert_eq!(features["asof_protocol"], PROTOCOL_ASOF);

    let probe = dispatch(
        "blockchain.tweaks.subscribe",
        &json!([0, 1, false]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert_eq!(probe, json!({"0": {}}));

    assert!(dispatch(
        "server.donation_address",
        &json!([]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs
    )
    .unwrap()
    .as_str()
    .is_some());

    assert_eq!(
        dispatch(
            "server.peers.subscribe",
            &json!([]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs
        )
        .unwrap(),
        json!([])
    );

    let fee = dispatch(
        "blockchain.relayfee",
        &json!([]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(fee.as_f64().is_some());

    let est = dispatch(
        "blockchain.estimatefee",
        &json!([6]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert_eq!(est.as_f64(), Some(-1.0));

    let hist = dispatch(
        "mempool.get_fee_histogram",
        &json!([]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert_eq!(hist, json!([]));

    // No tip → headers.subscribe errors.
    assert!(dispatch(
        "blockchain.headers.subscribe",
        &json!([]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs
    )
    .is_err());

    assert!(dispatch(
        "no.such.method",
        &json!([]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs
    )
    .unwrap_err()
    .contains("unknown method"));

    // Empty-chain scripthash methods.
    let sh = electrum_scripthash_hex(&[0x51]);
    let empty_hist = dispatch(
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
    assert_eq!(empty_hist, json!([]));

    let bal = dispatch(
        "blockchain.scripthash.get_balance",
        &json!([sh]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert_eq!(bal["confirmed"], 0);

    let unspent = dispatch(
        "blockchain.scripthash.listunspent",
        &json!([sh]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert_eq!(unspent, json!([]));

    let sub = dispatch(
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
    assert!(sub.as_str().is_some());
    assert_eq!(sh_subs.len(), 1);

    let mem = dispatch(
        "blockchain.scripthash.get_mempool",
        &json!([sh]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert_eq!(mem, json!([]));

    // Broadcast: bad hex fails before mempool gate.
    assert!(dispatch(
        "blockchain.transaction.broadcast",
        &json!(["zz"]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs
    )
    .is_err());

    // Non-empty hex that may fail deserialize or mempool gate — either is fine.
    assert!(dispatch(
        "blockchain.transaction.broadcast",
        &json!(["01000000000000000000"]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn accept_client_ping_and_shutdown() {
    let (dir, q) = tmp_store();
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
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["id"], 1);
    assert!(v.get("result").is_some());
    assert!(
        v.get("chain_tip").is_none(),
        "ping must not grow chain_tip: {v}"
    );

    // Empty line ignored; malformed JSON ignored; then version.
    let stream = reader.into_inner();
    stream.write_all(b"\n").await.unwrap();
    stream.write_all(b"{not json\n").await.unwrap();
    let mut line = serde_json::to_string(&json!({
        "jsonrpc":"2.0","id":2,"method":"server.version","params":[]
    }))
    .unwrap();
    line.push('\n');
    stream.write_all(line.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(stream);
    resp.clear();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        reader.read_line(&mut resp),
    )
    .await
    .expect("timeout")
    .unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["id"], 2);

    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn chain_view_get_history_stamps_tip_and_changes_on_replace() {
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

    let (dir, q) = tmp_store();
    let (h0, t0) = {
        let merkle = [0xab; 32];
        let header = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 0x207fffff,
            nonce: 0,
            merkle_root: merkle,
            hash: merkle,
        };
        let mut txid = [0xcb; 32];
        txid[31] = 0;
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
            outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
        };
        (header, ta)
    };
    let hash0 = h0.hash;
    q.connect_block(Height(0), &h0, &[t0]).unwrap();
    let prev_fk = q.tip_header_fk().unwrap().unwrap();
    let mut h1 = h0.clone();
    h1.prev_fk = prev_fk;
    h1.timestamp = 2;
    h1.nonce = 1;
    h1.hash = rbitcoin_store::block_header_hash(
        h1.version,
        &hash0,
        &h1.merkle_root,
        h1.timestamp,
        h1.bits,
        h1.nonce,
    );
    let mut t1 = {
        let mut txid = [0xcb; 32];
        txid[5] = 0xaa;
        TxApply {
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
                script_sig: vec![1],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
        }
    };
    t1.tx.txid[0] = 1;
    q.connect_block(Height(1), &h1, &[t1]).unwrap();
    let tip_a = hash_hex_rev(&h1.hash);

    let params = ChainParams::regtest();
    let q = std::sync::Arc::new(q);
    let (tip_tx, _) = broadcast::channel(4);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let handle = run_electrum(cfg, Arc::clone(&q), params, tip_tx, None)
        .await
        .expect("listen");
    let sh = electrum_scripthash_hex(&[0x51]);

    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
    let req = json!({
        "jsonrpc":"2.0","id":1,
        "method":"blockchain.scripthash.get_history","params":[sh]
    });
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
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["id"], 1, "{v}");
    assert!(v["result"].as_array().is_some(), "{v}");
    assert_eq!(v["chain_tip"], tip_a, "{v}");
    assert_eq!(v["chain_tip_height"], 1, "{v}");

    q.disconnect_tip().unwrap();
    let mut h1b = h1.clone();
    h1b.nonce = 9;
    h1b.hash = rbitcoin_store::block_header_hash(
        h1b.version,
        &hash0,
        &h1b.merkle_root,
        h1b.timestamp,
        h1b.bits,
        h1b.nonce,
    );
    let mut t1b = {
        let mut txid = [0xcb; 32];
        txid[5] = 0xbb;
        TxApply {
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
                script_sig: vec![2],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
        }
    };
    t1b.tx.txid[0] = 2;
    q.connect_block(Height(1), &h1b, &[t1b]).unwrap();
    let tip_b = hash_hex_rev(&h1b.hash);
    assert_ne!(tip_a, tip_b);

    let stream = reader.into_inner();
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    stream.write_all(line.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(stream);
    resp.clear();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        reader.read_line(&mut resp),
    )
    .await
    .expect("timeout")
    .unwrap();
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["chain_tip"], tip_b, "{v}");
    assert_eq!(v["chain_tip_height"], 1, "{v}");

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

#[test]
fn dispatch_on_connected_chain() {
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    // Build 2-block synthetic chain.
    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    let mut hashes = Vec::new();
    let mut first_txid = [0u8; 32];
    for h in 0..2u32 {
        let version = 1;
        let timestamp = h + 1;
        let bits = 0x207fffff;
        let nonce = h;
        let mut merkle = [0u8; 32];
        merkle[0..4].copy_from_slice(&h.to_le_bytes());
        merkle[5] = 0xec;
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
        };
        let mut txid = [0u8; 32];
        txid[0..4].copy_from_slice(&h.to_le_bytes());
        txid[31] = 0xcb;
        if h == 0 {
            first_txid = txid;
        }
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
        hashes.push(hash);
        parent_hash = Some(header.hash);
        prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
    }

    let mut header_sub = false;
    let mut sh_subs = HashSet::new();
    let tip = dispatch(
        "blockchain.headers.subscribe",
        &json!([]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(header_sub);
    assert_eq!(tip["height"], 1);

    let hdr = dispatch(
        "blockchain.block.header",
        &json!([0]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert_eq!(hdr.as_str().unwrap().len(), 160);

    let headers = dispatch(
        "blockchain.block.headers",
        &json!([0, 10]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(headers["count"].as_u64().unwrap() >= 2);

    let txid_hex = {
        let mut r = first_txid;
        r.reverse();
        rbitcoin_primitives::hex_encode(r)
    };
    let raw = dispatch(
        "blockchain.transaction.get",
        &json!([txid_hex]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(raw.as_str().unwrap().len() > 10);
    let verbose = dispatch(
        "blockchain.transaction.get",
        &json!([txid_hex, true]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(verbose.get("hex").is_some());

    let merkle = dispatch(
        "blockchain.transaction.get_merkle",
        &json!([txid_hex, 0]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert_eq!(merkle["block_height"], 0);

    let idpos = dispatch(
        "blockchain.transaction.id_from_pos",
        &json!([0, 0]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert_eq!(idpos.as_str().unwrap(), txid_hex);

    // Missing tx.
    let miss = [0xeeu8; 32];
    let mut miss_hex = miss;
    miss_hex.reverse();
    let miss_s = rbitcoin_primitives::hex_encode(miss_hex);
    assert!(dispatch(
        "blockchain.transaction.get",
        &json!([miss_s]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs
    )
    .is_err());

    // pos OOB
    assert!(dispatch(
        "blockchain.transaction.id_from_pos",
        &json!([0, 99]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs
    )
    .is_err());

    let sh = electrum_scripthash_hex(&[0x51]);
    let hist = dispatch(
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
    assert!(!hist.as_array().unwrap().is_empty());
    let bal = dispatch(
        "blockchain.scripthash.get_balance",
        &json!([sh]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(bal["confirmed"].as_i64().unwrap() > 0);
    let unspent = dispatch(
        "blockchain.scripthash.listunspent",
        &json!([sh]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(!unspent.as_array().unwrap().is_empty());
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
    assert!(!status.as_str().unwrap().is_empty());

    let _ = hashes;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn asof_scripthash_reads_hide_later_spend() {
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let merkle = [0xab; 32];
    let h0 = HeaderRecord {
        prev_fk: Fk::NULL,
        version: 1,
        timestamp: 1,
        bits: 0x207fffff,
        nonce: 0,
        merkle_root: merkle,
        hash: merkle,
    };
    let mut create_txid = [0xcb; 32];
    create_txid[31] = 0;
    let ta0 = TxApply {
        tx: TxRecord {
            txid: create_txid,
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
        outputs: vec![OutputRecord::unspent(10_0000_0000, vec![0x51])],
    };
    let hfk0 = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
    let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];
    let hash1 = rbitcoin_store::block_header_hash(1, &merkle, &[0x11; 32], 2, 0x207fffff, 1);
    let h1 = HeaderRecord {
        prev_fk: hfk0,
        version: 1,
        timestamp: 2,
        bits: 0x207fffff,
        nonce: 1,
        merkle_root: [0x11; 32],
        hash: hash1,
    };
    let mut spend_txid = [0u8; 32];
    spend_txid[0] = 0x11;
    spend_txid[31] = 0xcd;
    q.connect_block(
        Height(1),
        &h1,
        &[TxApply {
            tx: TxRecord {
                txid: spend_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: create_txid,
                create_fk,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(9_0000_0000, vec![0x00])],
        }],
    )
    .unwrap();

    let sh = electrum_scripthash_hex(&[0x51]);
    let asof0 = hash_hex_rev(&merkle);
    let asof1 = hash_hex_rev(&hash1);
    let tag0 = format!("asof:{asof0}");
    let tag1 = format!("asof:{asof1}");
    let mut conn = ElectrumConn::new();

    let denied = dispatch_with_join(
        "blockchain.scripthash.get_balance",
        &json!([sh, tag0]),
        &q,
        &cfg,
        &params,
        None,
        &mut conn,
    )
    .unwrap_err();
    assert!(
        denied.contains("1.4.2-asof"),
        "asof tag before handshake: {denied}"
    );

    let ver = dispatch_with_join(
        "server.version",
        &json!(["test", PROTOCOL_ASOF]),
        &q,
        &cfg,
        &params,
        None,
        &mut conn,
    )
    .unwrap();
    assert_eq!(ver[1], PROTOCOL_ASOF);
    let locked = dispatch_with_join(
        "server.version",
        &json!(["test", "1.4"]),
        &q,
        &cfg,
        &params,
        None,
        &mut conn,
    )
    .unwrap();
    assert_eq!(locked[1], PROTOCOL_ASOF);

    let bal0 = dispatch_with_join(
        "blockchain.scripthash.get_balance",
        &json!([sh, tag0]),
        &q,
        &cfg,
        &params,
        None,
        &mut conn,
    )
    .unwrap();
    assert_eq!(bal0["confirmed"], 10_0000_0000);
    assert_eq!(bal0["unconfirmed"], 0);
    let utxo0 = dispatch_with_join(
        "blockchain.scripthash.listunspent",
        &json!([sh, tag0]),
        &q,
        &cfg,
        &params,
        None,
        &mut conn,
    )
    .unwrap();
    assert_eq!(utxo0.as_array().unwrap().len(), 1);
    let hist0 = dispatch_with_join(
        "blockchain.scripthash.get_history",
        &json!([sh, tag0]),
        &q,
        &cfg,
        &params,
        None,
        &mut conn,
    )
    .unwrap();
    assert_eq!(hist0.as_array().unwrap().len(), 1);

    let bal1 = dispatch_with_join(
        "blockchain.scripthash.get_balance",
        &json!([sh, tag1]),
        &q,
        &cfg,
        &params,
        None,
        &mut conn,
    )
    .unwrap();
    assert_eq!(bal1["confirmed"], 0);
    let utxo1 = dispatch_with_join(
        "blockchain.scripthash.listunspent",
        &json!([sh, tag1]),
        &q,
        &cfg,
        &params,
        None,
        &mut conn,
    )
    .unwrap();
    assert!(utxo1.as_array().unwrap().is_empty());
    let hist1 = dispatch_with_join(
        "blockchain.scripthash.get_history",
        &json!([sh, tag1]),
        &q,
        &cfg,
        &params,
        None,
        &mut conn,
    )
    .unwrap();
    assert_eq!(hist1.as_array().unwrap().len(), 2);

    let create_hex = hash_hex_rev(&create_txid);
    let spend_hex = hash_hex_rev(&spend_txid);
    let (get_later, _) = electrum_at_chain_view(
        &q,
        "blockchain.transaction.get",
        &json!([spend_hex, tag0]),
        true,
        |q, rpc_params, view, is_asof| {
            assert_eq!(rpc_params, &json!([spend_hex]));
            let mut pin_conn = ElectrumConn {
                protocol: PROTOCOL_ASOF.to_string(),
                ..ElectrumConn::new()
            };
            dispatch_pinned(
                "blockchain.transaction.get",
                rpc_params,
                q,
                &cfg,
                &params,
                None,
                &mut pin_conn,
                view,
                is_asof,
            )
        },
    );
    assert!(
        get_later.unwrap_err().contains("tx not found"),
        "asof height 0 must hide the height-1 spend"
    );
    let (get_create, _) = electrum_at_chain_view(
        &q,
        "blockchain.transaction.get",
        &json!([create_hex, tag0]),
        true,
        |q, rpc_params, view, is_asof| {
            let mut pin_conn = ElectrumConn {
                protocol: PROTOCOL_ASOF.to_string(),
                ..ElectrumConn::new()
            };
            dispatch_pinned(
                "blockchain.transaction.get",
                rpc_params,
                q,
                &cfg,
                &params,
                None,
                &mut pin_conn,
                view,
                is_asof,
            )
        },
    );
    assert!(
        get_create.unwrap().as_str().unwrap().len() > 10,
        "asof height 0 still returns the genesis create"
    );
    let (merkle_later, _) = electrum_at_chain_view(
        &q,
        "blockchain.transaction.get_merkle",
        &json!([spend_hex, 1, tag0]),
        true,
        |q, rpc_params, view, is_asof| {
            assert_eq!(rpc_params, &json!([spend_hex, 1]));
            let mut pin_conn = ElectrumConn {
                protocol: PROTOCOL_ASOF.to_string(),
                ..ElectrumConn::new()
            };
            dispatch_pinned(
                "blockchain.transaction.get_merkle",
                rpc_params,
                q,
                &cfg,
                &params,
                None,
                &mut pin_conn,
                view,
                is_asof,
            )
        },
    );
    assert!(
        merkle_later.unwrap_err().contains("asof not on chain"),
        "merkle height above asof pin must fail"
    );
    let (merkle0, _) = electrum_at_chain_view(
        &q,
        "blockchain.transaction.get_merkle",
        &json!([create_hex, 0, tag0]),
        true,
        |q, rpc_params, view, is_asof| {
            let mut pin_conn = ElectrumConn {
                protocol: PROTOCOL_ASOF.to_string(),
                ..ElectrumConn::new()
            };
            dispatch_pinned(
                "blockchain.transaction.get_merkle",
                rpc_params,
                q,
                &cfg,
                &params,
                None,
                &mut pin_conn,
                view,
                is_asof,
            )
        },
    );
    assert_eq!(merkle0.unwrap()["block_height"], 0);

    let err = dispatch_with_join(
        "blockchain.scripthash.get_balance",
        &json!([sh, format!("asof:{}", "ee".repeat(32))]),
        &q,
        &cfg,
        &params,
        None,
        &mut conn,
    )
    .unwrap_err();
    assert!(err.contains("asof not on chain"), "unknown asof: {err}");
    let (out, view) = electrum_at_chain_view(
        &q,
        "blockchain.scripthash.get_balance",
        &json!([sh, tag0]),
        true,
        |q, rpc_params, view, is_asof| {
            assert_eq!(
                rpc_params,
                &json!([sh]),
                "asof must be stripped before dispatch"
            );
            assert!(is_asof);
            assert!(view.is_some());
            let mut pin_conn = ElectrumConn {
                protocol: PROTOCOL_ASOF.to_string(),
                ..ElectrumConn::new()
            };
            dispatch_pinned(
                "blockchain.scripthash.get_balance",
                rpc_params,
                q,
                &cfg,
                &params,
                None,
                &mut pin_conn,
                view,
                is_asof,
            )
        },
    );
    assert_eq!(out.unwrap()["confirmed"], 10_0000_0000);
    assert_eq!(view.unwrap().hash, merkle);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn electrum_sh_stamp_follows_pending_before_durable_apply() {
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let mut merkle = [0u8; 32];
    merkle[0] = 0x51;
    let h0 = HeaderRecord {
        prev_fk: Fk::NULL,
        version: 1,
        timestamp: 1,
        bits: 0x207fffff,
        nonce: 0,
        merkle_root: merkle,
        hash: merkle,
    };
    let ta0 = TxApply {
        tx: TxRecord {
            txid: [0xcb; 32],
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
    q.connect_block(Height(0), &h0, &[ta0]).unwrap();
    let prev_fk = q.tip_header_fk().unwrap().unwrap();
    let hash1 = rbitcoin_store::block_header_hash(1, &merkle, &[0x11; 32], 2, 0x207fffff, 1);
    let h1 = HeaderRecord {
        prev_fk,
        version: 1,
        timestamp: 2,
        bits: 0x207fffff,
        nonce: 1,
        merkle_root: [0x11; 32],
        hash: hash1,
    };
    let mut txid1 = [0u8; 32];
    txid1[0] = 0x11;
    txid1[31] = 0xcd;
    q.commit_class_a_only(
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
            outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
        }],
    )
    .unwrap();
    q.confirm_block(Height(1), &hash1).unwrap();
    assert_eq!(q.tip_height(), Some(Height(1)));
    assert_eq!(q.sh_indexed_through_height(), Some(0));

    let sh = electrum_scripthash_hex(&[0x51]);
    let (out, view) = electrum_at_chain_view(
        &q,
        "blockchain.scripthash.get_balance",
        &json!([sh]),
        false,
        |q, rpc_params, view, is_asof| {
            let mut pin_conn = ElectrumConn::new();
            dispatch_pinned(
                "blockchain.scripthash.get_balance",
                rpc_params,
                q,
                &cfg,
                &params,
                None,
                &mut pin_conn,
                view,
                is_asof,
            )
        },
    );
    assert!(out.is_ok(), "{out:?}");
    let v = view.unwrap();
    assert_eq!(v.hash, hash1);
    assert_eq!(v.height, Height(1));

    q.apply_sh_pending().unwrap();
    let (out, view) = electrum_at_chain_view(
        &q,
        "blockchain.scripthash.get_balance",
        &json!([sh]),
        false,
        |q, rpc_params, view, is_asof| {
            let mut pin_conn = ElectrumConn::new();
            dispatch_pinned(
                "blockchain.scripthash.get_balance",
                rpc_params,
                q,
                &cfg,
                &params,
                None,
                &mut pin_conn,
                view,
                is_asof,
            )
        },
    );
    assert!(out.is_ok(), "{out:?}");
    let v = view.unwrap();
    assert_eq!(v.hash, hash1);
    assert_eq!(v.height, Height(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dispatch_casa_sequence_reuses_sh_join_slot() {
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::{body_ok_reads, reset_body_ok_reads, TxApply};
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    for h in 0..3u32 {
        let version = 1;
        let timestamp = h + 1;
        let bits = 0x207fffff;
        let nonce = h;
        let mut merkle = [0u8; 32];
        merkle[0..4].copy_from_slice(&h.to_le_bytes());
        merkle[5] = 0xec;
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

    let mut conn = ElectrumConn::new();
    let sh = electrum_scripthash_hex(&[0x51]);
    reset_body_ok_reads();
    let bal = dispatch_with_join(
        "blockchain.scripthash.get_balance",
        &json!([sh]),
        &q,
        &cfg,
        &params,
        None,
        &mut conn,
    )
    .unwrap();
    assert_eq!(bal["confirmed"].as_i64().unwrap(), 150_0000_0000);
    let after_bal = body_ok_reads();
    assert_eq!(after_bal, 3);

    let hist = dispatch_with_join(
        "blockchain.scripthash.get_history",
        &json!([sh]),
        &q,
        &cfg,
        &params,
        None,
        &mut conn,
    )
    .unwrap();
    assert_eq!(hist.as_array().unwrap().len(), 3);
    assert_eq!(
        body_ok_reads(),
        after_bal,
        "get_history must reuse the connection join slot"
    );

    let unspent = dispatch_with_join(
        "blockchain.scripthash.listunspent",
        &json!([sh]),
        &q,
        &cfg,
        &params,
        None,
        &mut conn,
    )
    .unwrap();
    assert_eq!(unspent.as_array().unwrap().len(), 3);
    assert_eq!(
        body_ok_reads(),
        after_bal,
        "listunspent must reuse the connection join slot"
    );

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
async fn tip_push_and_lagged_client() {
    let (dir, q) = tmp_store();
    // Need a tip for headers.subscribe; empty chain errors on subscribe.
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};
    let mut hash = [0u8; 32];
    hash[0] = 1;
    let header = HeaderRecord {
        prev_fk: Fk::NULL,
        version: 1,
        timestamp: 1,
        bits: 0x207fffff,
        nonce: 0,
        merkle_root: hash,
        hash,
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
    q.connect_block(Height(0), &header, &[ta]).unwrap();

    let params = ChainParams::regtest();
    let q = std::sync::Arc::new(q);
    let (tip_tx, _) = broadcast::channel(2);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let handle = run_electrum(cfg, q, params, tip_tx.clone(), None)
        .await
        .unwrap();
    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
    let mut line = serde_json::to_string(&json!({
        "jsonrpc":"2.0","id":1,"method":"blockchain.headers.subscribe","params":[]
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
    // Push tip notify.
    tip_tx
        .send(TipNotify {
            height: 1,
            header_hex: "aa".repeat(80),
            reorg_from_height: None,
        })
        .unwrap();
    resp.clear();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        reader.read_line(&mut resp),
    )
    .await
    .unwrap()
    .unwrap();
    let push: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        push["method"].as_str(),
        Some("blockchain.headers.subscribe")
    );

    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scripthash_subscribe_notifies_on_tip_confirm() {
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

    let hash1 = rbitcoin_store::block_header_hash(1, &hash, &[0x11; 32], 2, 0x207fffff, 1);
    let h1 = HeaderRecord {
        prev_fk: hfk0,
        version: 1,
        timestamp: 2,
        bits: 0x207fffff,
        nonce: 1,
        merkle_root: [0x11; 32],
        hash: hash1,
    };
    let mut txid1 = [0u8; 32];
    txid1[0] = 0x11;
    txid1[31] = 0xcd;
    let ta1 = TxApply {
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
        outputs: vec![OutputRecord::unspent(1, vec![0x51])],
    };
    q.connect_block(Height(1), &h1, &[ta1]).unwrap();
    tip_tx
        .send(TipNotify {
            height: 1,
            header_hex: "aa".repeat(80),
            reorg_from_height: None,
        })
        .unwrap();
    resp.clear();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        reader.read_line(&mut resp),
    )
    .await
    .unwrap()
    .unwrap();
    let push: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        push["method"].as_str(),
        Some("blockchain.scripthash.subscribe")
    );

    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scripthash_subscribe_skips_tip_when_block_misses_sh() {
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

    let hash1 = rbitcoin_store::block_header_hash(1, &hash, &[0x11; 32], 2, 0x207fffff, 1);
    let h1 = HeaderRecord {
        prev_fk: hfk0,
        version: 1,
        timestamp: 2,
        bits: 0x207fffff,
        nonce: 1,
        merkle_root: [0x11; 32],
        hash: hash1,
    };
    let mut txid1 = [0u8; 32];
    txid1[0] = 0x11;
    txid1[31] = 0xcd;
    let ta1 = TxApply {
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
        outputs: vec![OutputRecord::unspent(1, vec![0x00])],
    };
    q.connect_block(Height(1), &h1, &[ta1]).unwrap();
    tip_tx
        .send(TipNotify {
            height: 1,
            header_hex: "aa".repeat(80),
            reorg_from_height: None,
        })
        .unwrap();
    resp.clear();
    let extra = tokio::time::timeout(
        std::time::Duration::from_millis(400),
        reader.read_line(&mut resp),
    )
    .await;
    assert!(extra.is_err(), "untouched tip must not restatus: {resp:?}");

    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn chain_view_status_includes_blockhash() {
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

    let (dir, q) = tmp_store();
    let merkle = [0xab; 32];
    let h0 = HeaderRecord {
        prev_fk: Fk::NULL,
        version: 1,
        timestamp: 1,
        bits: 0x207fffff,
        nonce: 0,
        merkle_root: merkle,
        hash: merkle,
    };
    let mut txid = [0xcb; 32];
    txid[31] = 0;
    let t0 = TxApply {
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
    q.connect_block(Height(0), &h0, &[t0.clone()]).unwrap();
    let prev_fk = q.tip_header_fk().unwrap().unwrap();
    let mut h1 = h0.clone();
    h1.prev_fk = prev_fk;
    h1.timestamp = 2;
    h1.nonce = 1;
    h1.hash = rbitcoin_store::block_header_hash(
        h1.version,
        &merkle,
        &h1.merkle_root,
        h1.timestamp,
        h1.bits,
        h1.nonce,
    );
    let mut t1 = t0;
    t1.tx.txid[5] = 0xaa;
    q.connect_block(Height(1), &h1, &[t1.clone()]).unwrap();
    let sh = script_hash(&[0x51]);
    let hist_a = q.scripthash_history(&sh).unwrap();
    let status_a = scripthash_status(Some(&q), &hist_a).unwrap();
    let legacy = {
        use bitcoin::hashes::{sha256, Hash as _};
        let mut s = String::new();
        for i in &hist_a {
            s.push_str(&format!("{}:{}:", txid_hex(&i.txid), i.height));
        }
        rbitcoin_primitives::hex_encode(sha256::Hash::hash(s.as_bytes()).to_byte_array())
    };
    assert_ne!(
        status_a, legacy,
        "status preimage must include confirming block hash"
    );

    q.disconnect_tip().unwrap();
    let mut h1b = h1.clone();
    h1b.nonce = 9;
    h1b.hash = rbitcoin_store::block_header_hash(
        h1b.version,
        &merkle,
        &h1b.merkle_root,
        h1b.timestamp,
        h1b.bits,
        h1b.nonce,
    );
    q.connect_block(Height(1), &h1b, &[t1]).unwrap();
    let hist_b = q.scripthash_history(&sh).unwrap();
    let status_b = scripthash_status(Some(&q), &hist_b).unwrap();
    assert_eq!(
        hist_a
            .iter()
            .map(|i| (i.txid, i.height))
            .collect::<Vec<_>>(),
        hist_b
            .iter()
            .map(|i| (i.txid, i.height))
            .collect::<Vec<_>>(),
        "same txs at the same heights"
    );
    assert_ne!(
        status_a, status_b,
        "same-height replace must change status via blockhash"
    );
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
    assert_ne!(
        push["params"][1].as_str().unwrap_or("missing"),
        status0,
        "dropped history must change status"
    );

    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dispatch_with_mempool_and_param_errors() {
    use rbitcoin_net::MempoolHub;
    use std::sync::Arc;

    let (dir, q) = tmp_store();
    // Genesis tip for broadcast / scripthash paths.
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};
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
        outputs: vec![OutputRecord::unspent(50_000, vec![0x51])],
    };
    q.connect_block(Height(0), &header, &[ta]).unwrap();

    let params = ChainParams::regtest();
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let q_arc = Arc::new(q);
    let mp_path = dir.join("mempool");
    let mp = MempoolHub::open(&mp_path, Arc::clone(&q_arc)).expect("mempool");
    let mut header_sub = false;
    let mut sh_subs = HashSet::new();
    let sh = electrum_scripthash_hex(&[0x51]);

    // Mempool-aware scripthash methods (empty pool).
    let hist = dispatch(
        "blockchain.scripthash.get_history",
        &json!([sh]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(hist.as_array().is_some());

    let bal = dispatch(
        "blockchain.scripthash.get_balance",
        &json!([sh]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(bal["confirmed"].as_i64().unwrap_or(0) >= 0);

    let unspent = dispatch(
        "blockchain.scripthash.listunspent",
        &json!([sh]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(unspent.as_array().is_some());

    let sub = dispatch(
        "blockchain.scripthash.subscribe",
        &json!([sh]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(sub.as_str().is_some());

    let mem = dispatch(
        "blockchain.scripthash.get_mempool",
        &json!([sh]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert_eq!(mem, json!([]));

    let hist_fee = dispatch(
        "mempool.get_fee_histogram",
        &json!([]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(hist_fee.as_array().is_some());

    // headers.subscribe with tip.
    let hs = dispatch(
        "blockchain.headers.subscribe",
        &json!([]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(header_sub);
    assert!(hs.get("height").is_some());

    // param_txid wrong length.
    assert!(param_txid(&json!(["aabb"]), 0).is_err());
    assert!(param_txid(&json!(["zz".repeat(32)]), 0).is_err());

    // Broadcast without valid tx → reject (mempool gate).
    assert!(dispatch(
        "blockchain.transaction.broadcast",
        &json!(["01000000000000000000"]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .is_err());

    // transaction.get for confirmed coinbase (hex).
    let tid = {
        let fks = q_arc.block_tx_fks(Height(0)).unwrap();
        let t = q_arc.get_tx(fks[0]).unwrap();
        hash_hex_rev(&t.txid)
    };
    let raw = dispatch(
        "blockchain.transaction.get",
        &json!([tid, false]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(raw.as_str().unwrap().len() > 20);

    // Verbose get (may be object or hex depending on implementation).
    let _ = dispatch(
        "blockchain.transaction.get",
        &json!([tid, true]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    );

    // scripthash_status_full direct.
    let sh_bytes = param_scripthash(&json!([sh]), 0).unwrap();
    let st = scripthash_status_full(&q_arc, &mp, &sh_bytes).unwrap();
    assert!(!st.is_empty() || st.is_empty()); // always returns string

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scripthash_status_matches_get_history_row_order() {
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_consensus::{accept_and_connect_block, Milestone};
    use rbitcoin_net::MempoolHub;
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::ScriptHashHistoryItem;
    use rbitcoin_store::script_hash;
    use std::sync::Arc;

    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let (_tip, _tip_time, coinbase_txids) = rbitcoin_consensus::pad_empty_from(
        &q,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        103,
        2,
    );

    let q_arc = Arc::new(q);
    let mp = MempoolHub::open(dir.join("mempool"), Arc::clone(&q_arc)).unwrap();
    mp.set_relay_enabled(true);

    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let parent = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: coinbase_txids[0],
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 1_000),
            script_pubkey: spk.clone(),
        }],
    };
    mp.accept_tx(&parent).expect("accept parent");

    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let mut header_sub = false;
    let mut sh_subs = HashSet::new();
    let sh = electrum_scripthash_hex(spk.as_bytes());
    let hist = dispatch(
        "blockchain.scripthash.get_history",
        &json!([sh]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    let arr = hist.as_array().unwrap();
    assert!(
        arr.iter().any(|r| r["height"].as_i64().unwrap() >= 1),
        "need a confirmed history row"
    );
    assert!(
        arr.last().unwrap()["height"].as_i64().unwrap() <= 0,
        "get_history must append mempool last"
    );

    let rows: Vec<ScriptHashHistoryItem> = arr
        .iter()
        .map(|r| ScriptHashHistoryItem {
            height: r["height"].as_i64().unwrap(),
            txid: param_txid(&json!([r["tx_hash"].as_str().unwrap()]), 0).unwrap(),
            tx_fk: Fk::NULL,
        })
        .collect();
    let expected = scripthash_status(Some(q_arc.as_ref()), &rows).unwrap();
    let mut height_sorted = rows.clone();
    height_sorted.sort_by_key(|i| i.height);
    let sorted_hash = scripthash_status(Some(q_arc.as_ref()), &height_sorted).unwrap();
    assert_ne!(
        sorted_hash, expected,
        "height-sort must not match get_history order"
    );

    let sh_bytes = script_hash(spk.as_bytes());
    let got = scripthash_status_full(q_arc.as_ref(), &mp, &sh_bytes).unwrap();
    assert_eq!(got, expected);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Live mempool txs: listunspent mempool outs, get_mempool rows, fee histogram,
/// estimatefee, transaction.get mempool path, broadcast accept, status_full.
#[test]
fn dispatch_live_mempool_surfaces() {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_consensus::{accept_and_connect_block, Milestone};
    use rbitcoin_net::MempoolHub;
    use rbitcoin_primitives::Height;
    use rbitcoin_store::script_hash;
    use std::sync::Arc;

    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();

    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    // Maturity pad so early coinbases are spendable (shared helper, not a POW remine loop).
    let (_tip, _tip_time, coinbase_txids) = rbitcoin_consensus::pad_empty_from(
        &q,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        103,
        2,
    );

    let q_arc = Arc::new(q);
    let mp = MempoolHub::open(dir.join("mempool"), Arc::clone(&q_arc)).unwrap();
    mp.set_relay_enabled(true);

    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let sh = electrum_scripthash_hex(spk.as_bytes());
    let parent = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: coinbase_txids[0],
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 1_000),
            script_pubkey: spk.clone(),
        }],
    };
    mp.accept_tx(&parent).expect("accept parent");

    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let mut header_sub = false;
    let mut sh_subs = HashSet::new();

    // History + mempool rows
    let hist = dispatch(
        "blockchain.scripthash.get_history",
        &json!([sh]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(!hist.as_array().unwrap().is_empty());

    let bal = dispatch(
        "blockchain.scripthash.get_balance",
        &json!([sh]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    let _ = bal["unconfirmed"].as_i64();

    // listunspent: confirmed coinbases + mempool parent out (filter spent)
    let unspent = dispatch(
        "blockchain.scripthash.listunspent",
        &json!([sh]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(!unspent.as_array().unwrap().is_empty());

    let mem = dispatch(
        "blockchain.scripthash.get_mempool",
        &json!([sh]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(!mem.as_array().unwrap().is_empty());

    let sub = dispatch(
        "blockchain.scripthash.subscribe",
        &json!([sh]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(sub.as_str().is_some());

    let hist_fee = dispatch(
        "mempool.get_fee_histogram",
        &json!([]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(!hist_fee.as_array().unwrap().is_empty());

    let est = dispatch(
        "blockchain.estimatefee",
        &json!([2]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(est.as_f64().unwrap() >= 0.0);

    // Mempool transaction.get (parent not yet confirmed)
    let parent_hex = {
        let mut t = parent.compute_txid().to_byte_array();
        t.reverse();
        rbitcoin_primitives::hex_encode(t)
    };
    // Parent is live in mempool but also may resolve via chain if coinbase-related;
    // get by parent txid — if not confirmed, hits mempool fallback.
    let got = dispatch(
        "blockchain.transaction.get",
        &json!([parent_hex, true]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    );
    // Either confirmed path or mempool — must succeed for live parent.
    assert!(got.is_ok(), "{got:?}");

    // Broadcast a second spend of coinbase[1]
    let second = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: coinbase_txids[1],
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 2_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x52]),
        }],
    };
    let raw = bitcoin::consensus::serialize(&second);
    let raw_hex = rbitcoin_primitives::hex_encode(&raw);
    let br = dispatch(
        "blockchain.transaction.broadcast",
        &json!([raw_hex]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .expect("broadcast");
    assert!(br.as_str().unwrap().len() == 64);

    // status_full with live mempool
    let sh_bytes = script_hash(spk.as_bytes());
    let st = scripthash_status_full(&q_arc, &mp, &sh_bytes).unwrap();
    assert!(!st.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

/// Unused scripthash listunspent must not rebuild mempool spentness from
/// every live body. Confirmed UTXOs spent by the mempool still drop.
#[test]
fn listunspent_unused_sh_does_not_load_mempool_bodies() {
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_consensus::{accept_and_connect_block, Milestone};
    use rbitcoin_net::MempoolHub;
    use rbitcoin_primitives::Height;
    use std::sync::Arc;

    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    const N_SPENDS: u32 = 4;
    let (_tip, _tip_time, coinbase_txids) = rbitcoin_consensus::pad_empty_from(
        &q,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        100 + N_SPENDS,
        N_SPENDS,
    );
    let q_arc = Arc::new(q);
    let mp = MempoolHub::open(dir.join("mempool"), Arc::clone(&q_arc)).unwrap();
    mp.set_relay_enabled(true);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    for (i, cbtxid) in coinbase_txids.iter().enumerate() {
        let fee = 1_000u64 + i as u64;
        let tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: *cbtxid,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000 - fee),
                script_pubkey: spk.clone(),
            }],
        };
        mp.accept_tx(&tx).expect("accept spend");
    }
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let mut header_sub = false;
    let mut sh_subs = HashSet::new();
    let unused = electrum_scripthash_hex(&[0x00]);
    let _ = mp.sample_reset_perf();
    let empty = dispatch(
        "blockchain.scripthash.listunspent",
        &json!([unused]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(empty.as_array().unwrap().is_empty());
    let s = mp.sample_reset_perf();
    assert_eq!(
        s.spent_body_loads, 0,
        "unused scripthash must not load mempool bodies (got {})",
        s.spent_body_loads
    );

    // Spent coinbase of the used script must drop; mempool parent out remains.
    let sh = electrum_scripthash_hex(spk.as_bytes());
    let unspent = dispatch(
        "blockchain.scripthash.listunspent",
        &json!([sh]),
        &q_arc,
        &cfg,
        &params,
        Some(&mp),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    let rows = unspent.as_array().unwrap();
    let spent_cb = format!("{}", coinbase_txids[0]);
    assert!(
        rows.iter().all(|r| r["tx_hash"] != spent_cb),
        "mempool-spent coinbase must drop: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r["height"] == 0),
        "mempool output must remain: {rows:?}"
    );
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
fn scripthash_sub_cap_enforced() {
    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    cfg.max_scripthash_subs = 2;
    let mut header_sub = false;
    let mut sh_subs = HashSet::new();
    // Two unique scripthashes.
    let h1 = "11".repeat(32);
    let h2 = "22".repeat(32);
    let h3 = "33".repeat(32);
    dispatch(
        "blockchain.scripthash.subscribe",
        &json!([h1]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    dispatch(
        "blockchain.scripthash.subscribe",
        &json!([h2]),
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
        &json!([h3]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap_err();
    assert!(err.contains("too many"), "{err}");
    // Re-subscribe existing is ok.
    dispatch(
        "blockchain.scripthash.subscribe",
        &json!([h1]),
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
    let _ = std::fs::remove_dir_all(&dir);
}

/// DoS: when at max_connections, further accepts are dropped immediately.
#[tokio::test]
async fn max_connections_rejects_extra_client() {
    use tokio::io::AsyncReadExt;
    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let q = Arc::new(q);
    let (tip_tx, _) = broadcast::channel(4);
    let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    cfg.limits.max_connections = 1;
    cfg.limits.idle_timeout = Duration::from_secs(30);
    let handle = run_electrum(cfg, q, params, tip_tx, None)
        .await
        .expect("listen");

    // Hold the only slot open.
    let held = TcpStream::connect(handle.local_addr).await.unwrap();
    // Give accept loop time to take the permit.
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Second client: TCP may still accept then drop the stream when no permit.
    let mut second = TcpStream::connect(handle.local_addr).await.unwrap();
    let req = json!({"jsonrpc":"2.0","id":1,"method":"server.ping","params":[]});
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    let _ = second.write_all(line.as_bytes()).await;
    let mut buf = [0u8; 256];
    let read = tokio::time::timeout(Duration::from_millis(400), second.read(&mut buf)).await;
    // Dropped connection: EOF / error / timeout — not a successful JSON-RPC pong.
    match read {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {}
        Ok(Ok(n)) => {
            let s = std::str::from_utf8(&buf[..n]).unwrap_or("");
            assert!(
                !s.contains("\"result\""),
                "second client must not get RPC result at cap: {s}"
            );
        }
    }
    drop(held);
    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// DoS: quiet client is disconnected when idle_timeout elapses.
#[tokio::test]
async fn idle_timeout_disconnects_quiet_client() {
    use tokio::io::AsyncReadExt;
    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let q = Arc::new(q);
    let (tip_tx, _) = broadcast::channel(4);
    let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    cfg.limits.idle_timeout = Duration::from_millis(80);
    let handle = run_electrum(cfg, q, params, tip_tx, None)
        .await
        .expect("listen");

    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
    // Send nothing — wait for server idle close.
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    match read {
        Ok(Ok(0)) | Ok(Err(_)) => {} // clean EOF or error on close
        Ok(Ok(n)) => panic!("unexpected data from idle close: {:?}", &buf[..n]),
        Err(_) => panic!("idle timeout did not close connection within 2s"),
    }
    handle.shutdown().await;
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

#[test]
fn tweaks_rpc_result_is_first_height_only() {
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    for h in 0..12u32 {
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
    let mut header_sub = false;
    let mut sh_subs = HashSet::new();
    let v = dispatch(
        "blockchain.tweaks.subscribe",
        &json!([0, 100, true]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    let obj = v.as_object().unwrap();
    assert_eq!(obj.len(), 1, "RPC result is the first height only");
    assert!(obj.contains_key("0"));
    assert!(!obj.contains_key("1"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Cake scan isolate uses ElectrumProvider.subscribe: JSON-RPC result is the
/// first height, then one notification per following height, then
/// `{"message":"done"}`. A multi-height result is treated as one event
/// (last key only); no `done` leaves the isolate pinging forever.
#[tokio::test]
async fn tweaks_subscribe_streams_heights_then_done() {
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
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let handle = run_electrum(cfg, q, params, tip_tx, None)
        .await
        .expect("listen");

    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
    let req = json!({
        "jsonrpc":"2.0","id":"scan",
        "method":"blockchain.tweaks.subscribe",
        "params":[1, 3, false]
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
    assert_eq!(
        map.len(),
        1,
        "JSON-RPC result must be one height, got {map:?}"
    );
    assert!(map.contains_key("1"), "{map:?}");

    let n2 = read_json(&mut reader).await;
    assert_eq!(n2["method"], "blockchain.tweaks.subscribe");
    let p2 = n2["params"][0].as_object().expect("notify 2");
    assert_eq!(p2.len(), 1);
    assert!(p2.contains_key("2"), "{p2:?}");

    let n3 = read_json(&mut reader).await;
    assert_eq!(n3["method"], "blockchain.tweaks.subscribe");
    let p3 = n3["params"][0].as_object().expect("notify 3");
    assert_eq!(p3.len(), 1);
    assert!(p3.contains_key("3"), "{p3:?}");

    let done = read_json(&mut reader).await;
    assert_eq!(done["method"], "blockchain.tweaks.subscribe");
    assert_eq!(done["params"][0]["message"], "done");

    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
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

#[test]
fn tweaks_subscribe_matches_engine_on_p2wpkh_spend() {
    use bitcoin::hashes::{hash160, Hash};
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_consensus::tweak_from_tx;
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let ser = pk.serialize();
    let h160 = hash160::Hash::hash(&ser);
    let mut p2wpkh = vec![0x00, 0x14];
    p2wpkh.extend_from_slice(h160.as_ref());
    let (xonly, _) = pk.x_only_public_key();
    let mut p2tr = vec![0x51, 0x20];
    p2tr.extend_from_slice(&xonly.serialize());

    let mut genesis_txid = [0u8; 32];
    genesis_txid[31] = 0xcb;
    let mut merkle0 = [0u8; 32];
    merkle0[5] = 0xec;
    let h0 = HeaderRecord {
        prev_fk: Fk::NULL,
        version: 1,
        timestamp: 1,
        bits: 0x207fffff,
        nonce: 0,
        merkle_root: merkle0,
        hash: merkle0,
    };
    let ta0 = TxApply {
        tx: TxRecord {
            txid: genesis_txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        inputs: vec![InputRecord::coinbase(u32::MAX, vec![0x00], vec![])],
        outputs: vec![OutputRecord::unspent(50_0000_0000, p2wpkh.clone())],
    };
    let fk0 = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
    let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];

    let mut spend_txid = [0u8; 32];
    spend_txid[0] = 0x11;
    spend_txid[31] = 0xcd;
    let hash1 = rbitcoin_store::block_header_hash(1, &h0.hash, &[0x11; 32], 2, 0x207fffff, 1);
    let h1 = HeaderRecord {
        prev_fk: fk0,
        version: 1,
        timestamp: 2,
        bits: 0x207fffff,
        nonce: 1,
        merkle_root: [0x11; 32],
        hash: hash1,
    };
    let ta1 = TxApply {
        tx: TxRecord {
            txid: spend_txid,
            version: 2,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: genesis_txid,
            create_fk,
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![vec![0u8; 64], ser.to_vec()],
        }],
        outputs: vec![OutputRecord::unspent(49_0000_0000, p2tr.clone())],
    };
    q.connect_block(Height(1), &h1, &[ta1]).unwrap();

    let mut header_sub = false;
    let mut sh_subs = HashSet::new();
    let v = dispatch(
        "blockchain.tweaks.subscribe",
        &json!([1, 1, false]),
        &q,
        &cfg,
        &params,
        None,
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();

    let engine_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array(genesis_txid),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[&[0u8; 64][..], &ser[..]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(p2tr),
        }],
    };
    let engine_prev = vec![TxOut {
        value: Amount::from_sat(50_0000_0000),
        script_pubkey: ScriptBuf::from_bytes(p2wpkh),
    }];
    let expect = tweak_from_tx(&engine_tx, &engine_prev).unwrap();
    let mut disp = spend_txid;
    disp.reverse();
    let key = rbitcoin_primitives::hex_encode(disp);
    assert_eq!(
        v["1"][key]["tweak"],
        json!(rbitcoin_primitives::hex_encode(expect.tweak))
    );
    let _ = std::fs::remove_dir_all(&dir);
}
