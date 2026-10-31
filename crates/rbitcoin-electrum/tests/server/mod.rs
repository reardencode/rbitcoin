use rbitcoin_consensus::ChainParams;
use rbitcoin_electrum::server::*;
use rbitcoin_net::MempoolHub;
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::Query;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::broadcast;

use rbitcoin_query::testutil::FixtureChain;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

fn tmp_store() -> (rbitcoin_query::testutil::TempDir, Query) {
    rbitcoin_query::testutil::tiny_query_labeled("electrum")
}

#[allow(clippy::cognitive_complexity)] // one fixture, many parser arms
#[test]
fn config_helpers_and_param_parsers() {
    let params = ChainParams::regtest();
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    assert_eq!(cfg.genesis_hash_hex, params.genesis_hash.to_string());
    assert!(cfg.banner.contains("rbitcoin"));
    assert_eq!(
        cfg.tweaks_min_dust,
        rbitcoin_electrum::tweaks::DEFAULT_TWEAKS_MIN_DUST
    );

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
    )
    .unwrap();
    assert!(h.is_some());
    assert_eq!(rest, json!([sh_hex]));
    let (rest_win, h_win) = take_trailing_asof(
        "blockchain.scripthash.get_history",
        &json!([sh_hex, 1, 10, tagged]),
    )
    .unwrap();
    assert!(h_win.is_some());
    assert_eq!(rest_win, json!([sh_hex, 1, 10]));
    let (rest_tx, h_tx) =
        take_trailing_asof("blockchain.transaction.get", &json!([sh_hex, tagged])).unwrap();
    assert!(h_tx.is_some());
    assert_eq!(rest_tx, json!([sh_hex]));
    let (rest_merkle, h_merkle) = take_trailing_asof(
        "blockchain.transaction.get_merkle",
        &json!([sh_hex, 0, tagged]),
    )
    .unwrap();
    assert!(h_merkle.is_some());
    assert_eq!(rest_merkle, json!([sh_hex, 0]));
    let (_, none) =
        take_trailing_asof("blockchain.scripthash.get_balance", &json!([sh_hex])).unwrap();
    assert!(none.is_none());
    let (_, not_hex) = take_trailing_asof(
        "blockchain.scripthash.get_balance",
        &json!([sh_hex, asof_hex]),
    )
    .unwrap();
    assert!(
        not_hex.is_none(),
        "bare trailing hex must not be asof (future positional hash args)"
    );
    let (_, leftover_obj) = take_trailing_asof(
        "blockchain.scripthash.get_balance",
        &json!([sh_hex, { "other": true }]),
    )
    .unwrap();
    assert!(leftover_obj.is_none());
    assert!(take_trailing_asof(
        "blockchain.scripthash.get_balance",
        &json!([sh_hex, "asof:zz"])
    )
    .unwrap_err()
    .contains("asof:<32-byte hex>"));
    let asof_tag = format!("asof:{}", "ab".repeat(32));
    let (_, ignored) =
        take_trailing_asof("blockchain.block.header", &json!([0, asof_tag])).unwrap();
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

    assert!(scripthash_status(&[]).is_empty());
    let one = scripthash_status(&[rbitcoin_query::ScriptHashHistoryItem {
        height: 1,
        txid: [1u8; 32],
        tx_fk: Fk::NULL,
        fee: None,
    }]);
    let preimage = format!("{}:1:", txid_hex(&[1u8; 32]));
    assert_eq!(
        one,
        rbitcoin_primitives::hex_encode(
            bitcoin::hashes::sha256::Hash::hash(preimage.as_bytes()).to_byte_array()
        ),
        "confirmed row status is tx_hash:height: with no block hash"
    );

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
            input_count: 1,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: [0u8; 32],
            parent: rbitcoin_store::InputParent::Coinbase,
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
                input_count: 1,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: [0u8; 32],
                parent: rbitcoin_store::InputParent::Coinbase,
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

/// One line, one byte at a time. A `BufReader` can pull the next server line
/// into its buffer and drop it, so a later read sees the wrong message.
async fn read_exact_line(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut byte))
            .await
            .expect("timeout")
            .unwrap();
        assert_ne!(n, 0, "electrum peer closed");
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    String::from_utf8(buf).unwrap()
}

pub(crate) async fn electrum_tcp_rpc(
    stream: &mut TcpStream,
    id: u32,
    method: &str,
    params: Value,
) -> Value {
    let req = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    stream.write_all(line.as_bytes()).await.unwrap();
    let resp = read_exact_line(stream).await;
    serde_json::from_str(&resp).unwrap()
}

fn dotted_at_least(version: &str, min: &[u64]) -> bool {
    let parts: Option<Vec<u64>> = version.split('.').map(|p| p.parse().ok()).collect();
    parts.is_some_and(|p| p.as_slice() >= min)
}

/// `server.version[0]` as the wallets that branch on it read it.
/// Sparrow `ElectrumServer.getServerCapability` (lowercased): batches when it
/// contains `electrumx`, or starts with `electrs/` and the version before the
/// first `-` is at least 0.9.0. BlueWallet `BlueElectrum.ts` (case-sensitive):
/// a string starting `ElectrumPersonalServer`, `electrs` or `Fulcrum` stops
/// batching unless the first space-separated word is `electrs` at 0.9.0 or
/// `Fulcrum` at 1.9.0 or later. Cake `getNodeIsElectrs` (lowercased) probes
/// tweaks only when it contains `electrs`.
fn assert_wallets_read(server: &str) {
    let lower = server.to_ascii_lowercase();
    let sparrow = lower.contains("electrumx")
        || lower
            .strip_prefix("electrs/")
            .is_some_and(|rest| dotted_at_least(rest.split('-').next().unwrap_or(""), &[0, 9, 0]));
    assert!(
        sparrow,
        "Sparrow would send one request per line for {server:?}"
    );
    let mut words = server.split(' ');
    let implementation = words.next().unwrap_or("");
    let version = words.next().unwrap_or("");
    let bluewallet = !["ElectrumPersonalServer", "electrs", "Fulcrum"]
        .iter()
        .any(|p| server.starts_with(p))
        || match implementation {
            "electrs" => dotted_at_least(version, &[0, 9, 0]),
            "Fulcrum" => dotted_at_least(version, &[1, 9, 0]),
            _ => false,
        };
    assert!(bluewallet, "BlueWallet would stop batching for {server:?}");
    assert!(
        lower.contains("electrs"),
        "Cake would skip the tweaks probe for {server:?}"
    );
}

pub(crate) async fn electrum_tcp_batch(stream: &mut TcpStream, items: &[Value]) -> Value {
    let mut line = serde_json::to_string(items).unwrap();
    line.push('\n');
    stream.write_all(line.as_bytes()).await.unwrap();
    serde_json::from_str(&read_exact_line(stream).await).unwrap()
}

#[allow(clippy::cognitive_complexity)] // one TCP client, every batch arm
#[tokio::test]
async fn batch_line_answers_every_item_in_one_array() {
    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let (tip_tx, _) = broadcast::channel(4);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let banner = cfg.banner.clone();
    let max_line = cfg.max_line_bytes();
    let handle = run_electrum(cfg, Arc::new(q), params, tip_tx, None)
        .await
        .expect("listen");
    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();

    let batch = electrum_tcp_batch(
        &mut stream,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"server.version","params":["Sparrow",["1.3","1.4.2"]]}),
            json!({"jsonrpc":"2.0","id":"two","method":"server.ping","params":[]}),
            json!({"jsonrpc":"2.0","id":3,"method":"no.such.method","params":[]}),
            json!({"jsonrpc":"2.0","id":4,"method":"blockchain.tweaks.subscribe","params":[0,1,false]}),
            json!({"jsonrpc":"2.0","id":5,"method":"blockchain.silentpayments.subscribe","params":[]}),
            json!({"jsonrpc":"2.0","id":6,"method":"server.banner","params":[]}),
        ],
    )
    .await;
    let items = batch
        .as_array()
        .expect("a batch line is answered by one array");
    let ids: Vec<&Value> = items.iter().map(|v| &v["id"]).collect();
    assert_eq!(
        ids,
        [
            &json!(1),
            &json!("two"),
            &json!(3),
            &json!(4),
            &json!(5),
            &json!(6)
        ],
        "{batch}"
    );
    assert!(items.iter().all(|v| v["jsonrpc"] == "2.0"), "{batch}");
    assert_wallets_read(items[0]["result"][0].as_str().unwrap());
    assert_eq!(
        items[0]["result"][1], "1.4.2",
        "Sparrow offers [1.3, 1.4.2]"
    );
    assert!(items[1]["result"].is_null() && items[1].get("error").is_none());
    assert!(
        items[2]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown method"),
        "{batch}"
    );
    for streaming in &items[3..5] {
        assert!(streaming.get("result").is_none(), "{streaming}");
        assert!(
            streaming["error"]["message"]
                .as_str()
                .unwrap()
                .contains("batch"),
            "{streaming}"
        );
    }
    assert_eq!(items[5]["result"].as_str(), Some(banner.as_str()));
    let ping = electrum_tcp_rpc(&mut stream, 7, "server.ping", json!([])).await;
    assert_eq!(
        ping["id"], 7,
        "a rejected stream must not write lines after the batch: {ping}"
    );

    stream.write_all(b"[]\n").await.unwrap();
    let empty: Value = serde_json::from_str(&read_exact_line(&mut stream).await).unwrap();
    assert_eq!(
        empty,
        json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"empty batch"}})
    );

    let page: Vec<Value> = (0..100u32)
        .map(|i| {
            json!({"jsonrpc":"2.0","id":i,"method":"blockchain.scripthash.get_balance",
                   "params":[format!("{i:064x}")]})
        })
        .collect();
    assert!(serde_json::to_string(&page).unwrap().len() < max_line);
    let answered = electrum_tcp_batch(&mut stream, &page).await;
    let answered = answered.as_array().expect("array");
    assert_eq!(answered.len(), 100);
    for (i, v) in answered.iter().enumerate() {
        assert_eq!(v["id"], i, "{v}");
        assert!(v.get("result").is_some() != v.get("error").is_some(), "{v}");
    }

    let mut oversize: Vec<Value> = (0..MAX_BATCH_ITEMS)
        .map(|i| json!({"jsonrpc":"2.0","id":i,"method":"server.ping","params":[]}))
        .collect();
    let full = electrum_tcp_batch(&mut stream, &oversize).await;
    assert_eq!(full.as_array().map(Vec::len), Some(MAX_BATCH_ITEMS));
    oversize.push(json!({"jsonrpc":"2.0","id":"over","method":"server.ping","params":[]}));
    assert_eq!(
        electrum_tcp_batch(&mut stream, &oversize).await,
        json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"batch too large"}})
    );
    let ping = electrum_tcp_rpc(&mut stream, 8, "server.ping", json!([])).await;
    assert_eq!(ping["id"], 8);

    let mixed = electrum_tcp_batch(
        &mut stream,
        &[
            json!({"jsonrpc":"2.0","method":"server.ping","params":[]}),
            json!({"jsonrpc":"2.0","id":null,"method":"server.ping","params":[]}),
            json!(1),
            json!("x"),
        ],
    )
    .await;
    let invalid = json!({"code":-32600,"message":"Invalid Request"});
    assert_eq!(
        mixed,
        json!([
            {"jsonrpc":"2.0","id":null,"result":null},
            {"jsonrpc":"2.0","id":null,"error":invalid},
            {"jsonrpc":"2.0","id":null,"error":invalid},
        ]),
        "a notification gets no slot; an explicit null id does"
    );

    let notes = [
        json!({"jsonrpc":"2.0","method":"server.ping","params":[]}),
        json!({"jsonrpc":"2.0","method":"blockchain.tweaks.subscribe","params":[0,1,false]}),
    ];
    let mut line = serde_json::to_string(&notes).unwrap();
    line.push('\n');
    stream.write_all(line.as_bytes()).await.unwrap();
    let ping = electrum_tcp_rpc(&mut stream, 9, "server.ping", json!([])).await;
    assert_eq!(
        ping,
        json!({"jsonrpc":"2.0","id":9,"result":null}),
        "a batch of notifications writes nothing"
    );

    let noted = format!("{:064x}", 0xabc);
    let watched = format!("{:064x}", 0xdef);
    let subs = [
        json!({"jsonrpc":"2.0","method":"blockchain.scripthash.subscribe","params":[noted]}),
        json!({"jsonrpc":"2.0","id":10,"method":"blockchain.scripthash.subscribe","params":[watched]}),
    ];
    let reply = electrum_tcp_batch(&mut stream, &subs).await;
    assert_eq!(reply.as_array().map(Vec::len), Some(1), "{reply}");
    assert!(reply[0].get("result").is_some(), "{reply}");
    let unsub = "blockchain.scripthash.unsubscribe";
    let was = electrum_tcp_rpc(&mut stream, 11, unsub, json!([watched])).await;
    assert_eq!(was["result"], json!(true), "{was}");
    let was = electrum_tcp_rpc(&mut stream, 12, unsub, json!([noted])).await;
    assert_eq!(
        was["result"],
        json!(false),
        "a notification is skipped, so it subscribes nothing: {was}"
    );

    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A read-only batch still completes when the node-wide budget is 1.
/// Holding that permit stalls the batch; releasing it lets the batch finish.
#[tokio::test]
async fn read_only_batch_completes_when_the_store_budget_is_one() {
    let (dir, q) = tmp_store();
    q.set_api_read_budget(1);
    let q = Arc::new(q);
    let params = ChainParams::regtest();
    let (tip_tx, _) = broadcast::channel(4);
    let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    cfg.batch_window = 4;
    let handle = run_electrum(cfg, Arc::clone(&q), params, tip_tx, None)
        .await
        .expect("listen");
    let items: Vec<Value> = (0..3)
        .map(|id| {
            json!({"jsonrpc":"2.0","id":id,"method":"blockchain.scripthash.get_balance",
                   "params":[format!("{id:064x}")]})
        })
        .collect();
    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
    let reply = tokio::time::timeout(
        Duration::from_secs(5),
        electrum_tcp_batch(&mut stream, &items),
    )
    .await
    .expect("budget 1 serializes the batch; it must not fail")
    .as_array()
    .expect("batch array")
    .clone();
    assert_eq!(reply.len(), 3, "{reply:?}");

    let hold = q.api_read_budget().acquire_owned().await.expect("permit");
    let mut stalled = TcpStream::connect(handle.local_addr).await.unwrap();
    let mut line = serde_json::to_string(&items).unwrap();
    line.push('\n');
    stalled.write_all(line.as_bytes()).await.unwrap();
    let early =
        tokio::time::timeout(Duration::from_millis(200), read_exact_line(&mut stalled)).await;
    assert!(early.is_err(), "the batch must wait for the held permit");
    drop(hold);
    let late = tokio::time::timeout(Duration::from_secs(5), read_exact_line(&mut stalled))
        .await
        .expect("batch finishes after the permit is released");
    let parsed: Value = serde_json::from_str(&late).unwrap();
    assert_eq!(parsed.as_array().expect("array").len(), 3, "{parsed}");
    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A subscription restatus waits for the store budget on the connection task.
/// The only blocking-pool thread stays free for other work during that wait.
#[test]
fn subscription_restatus_waits_without_a_pool_thread() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let (dir, q) = tmp_store();
        q.set_api_read_budget(1);
        let q = Arc::new(q);
        let hold = q.api_read_budget().acquire_owned().await.expect("permit");
        let (_read, write) = tokio::io::duplex(256);
        let mut writer = ConnWrite::new(write, Duration::from_secs(2));
        let subs = HashSet::new();
        let mut last = HashMap::new();
        let q2 = Arc::clone(&q);
        let notes = tokio::spawn(async move {
            emit_sh_notes(&mut writer, &q2, None, &subs, &mut last, None).await
        });
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(
            !notes.is_finished(),
            "restatus ran while the store permit was held"
        );
        let probe = tokio::time::timeout(Duration::from_secs(2), tokio::task::spawn_blocking(|| 7))
            .await
            .expect("the budget wait must leave the blocking pool free")
            .expect("probe join");
        assert_eq!(probe, 7);
        assert!(
            !notes.is_finished(),
            "restatus took the pool thread to wait"
        );
        drop(hold);
        tokio::time::timeout(Duration::from_secs(2), notes)
            .await
            .expect("restatus finishes after the permit is released")
            .expect("join")
            .expect("restatus");
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[cfg(debug_assertions)]
fn get_balance(id: usize) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"blockchain.scripthash.get_balance",
           "params":[format!("{id:064x}")]})
}

#[cfg(debug_assertions)]
fn spawned(trace: &[BatchStep]) -> Vec<usize> {
    trace
        .iter()
        .filter_map(|s| match s {
            BatchStep::Spawn(i) => Some(*i),
            _ => None,
        })
        .collect()
}

#[cfg(debug_assertions)]
fn written(trace: &[BatchStep]) -> Vec<usize> {
    trace
        .iter()
        .filter_map(|s| match s {
            BatchStep::Write(i) => Some(*i),
            _ => None,
        })
        .collect()
}

#[cfg(debug_assertions)]
fn at(trace: &[BatchStep], step: BatchStep) -> usize {
    trace
        .iter()
        .position(|s| *s == step)
        .unwrap_or_else(|| panic!("{step:?} missing from {trace:?}"))
}

#[test]
fn batch_window_is_half_the_blocking_pool() {
    assert_eq!(batch_window(1), 1);
    assert_eq!(batch_window(MIN_BLOCKING_POOL), 2);
    assert_eq!(batch_window(12), 6);
    let params = ChainParams::regtest();
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    assert_eq!(cfg.batch_window, 2, "the smallest pool the node builds");
}

/// Read-only batch items run up to the configured window at a time and land
/// in request order. A subscribe waits for every earlier read to be written,
/// runs alone, and later items see what it did. The connection task runs on
/// this thread (current-thread runtime), so the armed trace sees its steps.
#[cfg(debug_assertions)]
#[tokio::test]
async fn batch_reads_overlap_and_land_in_request_order() {
    for window in [1, 2, 4] {
        reads_overlap_in_window(window).await;
    }
}

#[cfg(debug_assertions)]
#[allow(clippy::cognitive_complexity)] // one batch, every scheduling rule
async fn reads_overlap_in_window(window: usize) {
    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let (tip_tx, _) = broadcast::channel(4);
    let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    cfg.batch_window = window;
    let handle = run_electrum(cfg, Arc::new(q), params, tip_tx, None)
        .await
        .expect("listen");
    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();

    let watched = format!("{:064x}", 0xabc);
    let mut items: Vec<Value> = (0..6).map(get_balance).collect();
    items.push(json!({"jsonrpc":"2.0","id":6,"method":"blockchain.scripthash.subscribe","params":[watched]}));
    items.extend((7..10).map(get_balance));
    items.push(json!({"jsonrpc":"2.0","id":10,"method":"blockchain.scripthash.unsubscribe","params":[watched]}));
    items.push(
        json!({"jsonrpc":"2.0","method":"blockchain.scripthash.get_balance","params":[watched]}),
    );
    items.push(json!(12));

    batch_trace_arm();
    let reply = electrum_tcp_batch(&mut stream, &items).await;
    let trace = batch_trace_snapshot();
    batch_trace_clear();

    let ids: Vec<Value> = reply
        .as_array()
        .expect("one array line")
        .iter()
        .map(|v| v["id"].clone())
        .collect();
    let mut want: Vec<Value> = (0..=10).map(|i| json!(i)).collect();
    want.push(Value::Null);
    assert_eq!(ids, want, "{reply}");
    assert_eq!(
        reply[10]["result"],
        json!(true),
        "the subscribe ran before the unsubscribe: {reply}"
    );

    assert_eq!(written(&trace), [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12]);
    assert_eq!(spawned(&trace), [0, 1, 2, 3, 4, 5, 7, 8, 9], "{trace:?}");
    let mut open = 0usize;
    let mut peak = 0usize;
    for step in &trace {
        match step {
            BatchStep::Spawn(_) => open += 1,
            BatchStep::Write(i) if spawned(&trace).contains(i) => open -= 1,
            _ => {}
        }
        peak = peak.max(open);
    }
    assert_eq!(peak, window, "{trace:?}");
    assert_eq!(
        at(&trace, BatchStep::Spawn(1)) < at(&trace, BatchStep::Write(0)),
        window > 1,
        "reads overlap only in a window above one: {trace:?}"
    );
    for barrier in [6, 10] {
        assert!(
            at(&trace, BatchStep::Write(barrier - 1)) < at(&trace, BatchStep::Serial(barrier)),
            "{barrier} waits for earlier reads: {trace:?}"
        );
    }
    assert!(
        at(&trace, BatchStep::Write(6)) < at(&trace, BatchStep::Spawn(7)),
        "reads after a subscribe start after it: {trace:?}"
    );

    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A client that stops reading stops the batch: the server writes slot i
/// before it starts read i + window.
#[cfg(debug_assertions)]
#[tokio::test]
async fn stalled_batch_reader_holds_reads_to_the_window() {
    for window in [1, 3] {
        stalled_reader_in_window(window).await;
    }
}

#[cfg(debug_assertions)]
async fn stalled_reader_in_window(window: usize) {
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    struct OnceRead(Vec<u8>);
    impl AsyncRead for OnceRead {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.0.is_empty() {
                return Poll::Pending;
            }
            let n = this.0.len().min(buf.remaining());
            buf.put_slice(&this.0[..n]);
            this.0.drain(..n);
            Poll::Ready(Ok(()))
        }
    }
    /// Takes the first write, then never another.
    struct OneWrite {
        took: bool,
        stalled: Arc<AtomicBool>,
    }
    impl AsyncWrite for OneWrite {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if this.took {
                this.stalled.store(true, Ordering::SeqCst);
                return Poll::Pending;
            }
            this.took = true;
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    struct Duplex(OnceRead, OneWrite);
    impl AsyncRead for Duplex {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for Duplex {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().1).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().1).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().1).poll_shutdown(cx)
        }
    }

    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    cfg.batch_window = window;
    let items: Vec<Value> = (0..20).map(get_balance).collect();
    let mut line = serde_json::to_vec(&items).unwrap();
    line.push(b'\n');
    let stalled = Arc::new(AtomicBool::new(false));
    let (_tip_tx, tip_rx) = broadcast::channel(1);
    batch_trace_arm();
    let task = tokio::spawn(handle_client(
        Duplex(
            OnceRead(line),
            OneWrite {
                took: false,
                stalled: Arc::clone(&stalled),
            },
        ),
        "127.0.0.1:9".parse().unwrap(),
        Arc::new(q),
        Arc::new(cfg),
        Arc::new(params),
        tip_rx,
        None,
        Arc::new(AtomicBool::new(false)),
    ));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !stalled.load(Ordering::SeqCst) {
        assert!(
            Instant::now() < deadline,
            "the second slot was never written"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let trace = batch_trace_snapshot();
    batch_trace_clear();
    task.abort();
    assert_eq!(written(&trace), [0, 1], "{trace:?}");
    assert_eq!(
        spawned(&trace),
        (0..=window).collect::<Vec<_>>(),
        "slot 0 is written before read {window} starts, and slot 1 blocks the rest: {trace:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A batch reply goes to the socket one slot per write, so a client that
/// reads slowly holds the server to about one reply, not the whole array.
#[tokio::test]
async fn batch_reply_is_written_one_slot_at_a_time() {
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    struct OnceRead(Vec<u8>);
    impl AsyncRead for OnceRead {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.0.is_empty() {
                return Poll::Pending;
            }
            let n = this.0.len().min(buf.remaining());
            buf.put_slice(&this.0[..n]);
            this.0.drain(..n);
            Poll::Ready(Ok(()))
        }
    }
    #[derive(Default)]
    struct Seen {
        bytes: Vec<u8>,
        largest_write: usize,
    }
    struct Recorder(Arc<Mutex<Seen>>);
    impl AsyncWrite for Recorder {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let mut seen = self.0.lock().unwrap();
            seen.largest_write = seen.largest_write.max(buf.len());
            seen.bytes.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    struct Duplex(OnceRead, Recorder);
    impl AsyncRead for Duplex {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for Duplex {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().1).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().1).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().1).poll_shutdown(cx)
        }
    }

    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    cfg.banner = "b".repeat(64 * 1024);
    let slots = 40;
    let batch: Vec<Value> = (0..slots)
        .map(|i| json!({"jsonrpc":"2.0","id":i,"method":"server.banner","params":[]}))
        .collect();
    let mut line = serde_json::to_vec(&batch).unwrap();
    line.push(b'\n');
    let seen = Arc::new(Mutex::new(Seen::default()));
    let (_tip_tx, tip_rx) = broadcast::channel(1);
    let task = tokio::spawn(handle_client(
        Duplex(OnceRead(line), Recorder(Arc::clone(&seen))),
        "127.0.0.1:9".parse().unwrap(),
        Arc::new(q),
        Arc::new(cfg),
        Arc::new(params),
        tip_rx,
        None,
        Arc::new(AtomicBool::new(false)),
    ));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !seen.lock().unwrap().bytes.ends_with(b"]\n") {
        assert!(Instant::now() < deadline, "batch reply never finished");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    task.abort();
    let seen = seen.lock().unwrap();
    assert_eq!(
        seen.bytes.iter().filter(|b| **b == b'\n').count(),
        1,
        "still one line"
    );
    let reply: Value = serde_json::from_slice(&seen.bytes).unwrap();
    let reply = reply.as_array().unwrap();
    assert_eq!(reply.len(), slots);
    assert!(reply.iter().enumerate().all(|(i, v)| v["id"] == i));
    assert!(
        seen.largest_write < 2 * 64 * 1024,
        "largest write {} bytes for a {} byte reply",
        seen.largest_write,
        seen.bytes.len()
    );
    let _ = std::fs::remove_dir_all(&dir);
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
        cake_server.to_ascii_lowercase().contains("rbitcoin"),
        "version[0] must still identify rbitcoin, got {cake_server:?}"
    );
    assert!(
        cake_server.contains(env!("CARGO_PKG_VERSION")),
        "version[0] must track workspace.package.version, got {cake_server:?}"
    );
    assert_wallets_read(cake_server);
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
    let done: Value = serde_json::from_str(&read_exact_line(&mut stream).await).unwrap();
    assert_eq!(done["method"], "blockchain.tweaks.subscribe");
    assert_eq!(done["params"][0]["message"], "done");

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

#[tokio::test]
async fn electrum_fee_reports_follow_configured_and_enforced_floor() {
    let (dir, q) = tmp_store();
    let q = std::sync::Arc::new(q);
    let mp =
        MempoolHub::open_with_weight(dir.join("mempool"), std::sync::Arc::clone(&q), 0).unwrap();
    mp.set_min_relay_sat_kvb(2_500);
    let params = ChainParams::regtest();
    let (tip_tx, _) = broadcast::channel(4);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let handle = run_electrum(cfg, q, params, tip_tx, Some(mp))
        .await
        .expect("listen");
    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
    let info = electrum_tcp_rpc(&mut stream, 1, "mempool.get_info", json!([])).await;
    let relay = electrum_tcp_rpc(&mut stream, 2, "blockchain.relayfee", json!([])).await;
    let sats = |v: &Value| (v.as_f64().unwrap() * 100_000_000.0).round() as u64;
    assert_eq!(sats(&info["result"]["minrelaytxfee"]), 2_500, "{info}");
    assert_eq!(sats(&info["result"]["mempoolminfee"]), 2_600, "{info}");
    assert_eq!(sats(&info["result"]["incrementalrelayfee"]), 100, "{info}");
    assert_eq!(sats(&relay["result"]), 2_600, "{relay}");
    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// On a 1-worker runtime, ping must complete while another socket is inside
/// a real blocking store query (`blockchain.block.headers`).
#[tokio::test(flavor = "current_thread")]
async fn ping_overlaps_blocking_headers_on_one_worker() {
    use rbitcoin_consensus::Milestone;
    use rbitcoin_primitives::Height;
    use rbitcoin_query::accept_and_connect_block;
    use std::sync::atomic::AtomicU64;

    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    // Enough headers that a serial walk stays in-flight after ping is scheduled.
    let _ = rbitcoin_query::pad_empty_from(
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
                input_count: 1,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: [0u8; 32],
                parent: rbitcoin_store::InputParent::Coinbase,
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
    assert_eq!(scripthash_status(&full_hist), status_s);

    let _ = prev;
    let _ = std::fs::remove_dir_all(&dir);
}

/// One block paying `0x51`, a pool, and a connection over a pipe that has
/// subscribed to that script and read its confirmed status. The tests pause
/// the clock, so a tick fires only when one advances it.
struct HeldPoolPad {
    dir: rbitcoin_query::testutil::TempDir,
    q: Arc<Query>,
    mp: Arc<MempoolHub>,
    tip_tx: broadcast::Sender<TipNotify>,
    client: BufReader<tokio::io::DuplexStream>,
    sh: String,
}

impl HeldPoolPad {
    async fn read(&mut self) -> Value {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), self.client.read_line(&mut line))
            .await
            .expect("a line from the server")
            .unwrap();
        serde_json::from_str(&line).unwrap()
    }

    async fn call(&mut self, id: u32, method: &str, params: Value) -> Value {
        let req = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
        let mut line = serde_json::to_string(&req).unwrap();
        line.push('\n');
        self.client
            .get_mut()
            .write_all(line.as_bytes())
            .await
            .unwrap();
        self.read().await
    }
}

async fn held_pool_pad() -> HeldPoolPad {
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

    let (dir, q) = tmp_store();
    let mut hash = [0u8; 32];
    hash[0] = 0x44;
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
    txid[31] = 0xce;
    let ta = TxApply {
        tx: TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: [0u8; 32],
            parent: rbitcoin_store::InputParent::Coinbase,
            sequence: u32::MAX,
            script_sig: vec![0],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(1, vec![0x51])],
    };
    q.connect_block(Height(0), &header, &[ta]).unwrap();
    let params = ChainParams::regtest();
    let q = Arc::new(q);
    let mp = MempoolHub::open(dir.join("mempool"), Arc::clone(&q)).unwrap();
    let (tip_tx, tip_rx) = broadcast::channel(4);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let (client, server) = tokio::io::duplex(1 << 16);
    tokio::spawn(handle_client(
        server,
        "127.0.0.1:9".parse().unwrap(),
        Arc::clone(&q),
        Arc::new(cfg),
        Arc::new(params),
        tip_rx,
        Some(Arc::clone(&mp)),
        Arc::new(AtomicBool::new(false)),
    ));
    let mut pad = HeldPoolPad {
        dir,
        q,
        mp,
        tip_tx,
        client: BufReader::new(client),
        sh: electrum_scripthash_hex(&[0x51]),
    };
    let sh = pad.sh.clone();
    let first = pad
        .call(1, "blockchain.scripthash.subscribe", json!([sh]))
        .await;
    assert!(!first["result"].as_str().unwrap().is_empty(), "{first}");
    pad
}

/// Replace block 0 with one paying `0x00`, so the scripthash watermark ends
/// where it started and only a read held back for the pool can notice.
fn replace_block(q: &Query) {
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

    q.disconnect_tip().unwrap();
    let mut hash = [0u8; 32];
    hash[0] = 0x45;
    let header = HeaderRecord {
        prev_fk: Fk::NULL,
        version: 1,
        timestamp: 1,
        bits: 0x207fffff,
        nonce: 1,
        merkle_root: hash,
        hash,
        size: 0,
        weight: 0,
    };
    let mut txid = [0u8; 32];
    txid[0] = 0x98;
    txid[31] = 0xcf;
    let ta = TxApply {
        tx: TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: [0u8; 32],
            parent: rbitcoin_store::InputParent::Coinbase,
            sequence: u32::MAX,
            script_sig: vec![1],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(1, vec![0x00])],
    };
    q.connect_block(Height(0), &header, &[ta]).unwrap();
}

/// The server polls ticks and events before the next request, so a ping
/// answered with nothing ahead of it means those reads pushed nothing. Once
/// the pool is released, the next tick pushes the dropped script's null.
async fn ping_then_null_push(
    pad: &mut HeldPoolPad,
    hold: rbitcoin_net::tx_relay::TemplateHold<'_>,
) {
    assert_eq!(pad.mp.pool_settle_gen() % 2, 1, "the hold is out");
    let ping = pad.call(9, "server.ping", json!([])).await;
    assert_eq!(ping["id"], 9, "pushed while the pool was held: {ping}");
    drop(hold);
    assert_eq!(pad.mp.pool_settle_gen() % 2, 0, "the hold is back");
    tokio::time::advance(Duration::from_millis(60)).await;
    let push = pad.read().await;
    assert_eq!(push["method"], "blockchain.scripthash.subscribe", "{push}");
    assert_eq!(push["params"][0], json!(pad.sh), "{push}");
    assert_eq!(push["params"][1], Value::Null, "{push}");
}

/// A reorg holds the template mark until its disconnected txs are back in
/// the pool. A tick that sees the watermark walk back in that hold pushes
/// nothing.
#[tokio::test(start_paused = true)]
async fn tick_waits_for_the_pool_after_a_reorg() {
    let mut pad = held_pool_pad().await;
    let mp = Arc::clone(&pad.mp);
    let hold = mp.template_hold();
    pad.q.disconnect_tip().unwrap();
    tokio::time::advance(Duration::from_millis(60)).await;
    ping_then_null_push(&mut pad, hold).await;
    let _ = std::fs::remove_dir_all(&pad.dir);
}

/// A tip event of an earlier reorg can be read while a later one holds the
/// pool. That restatus waits too, and the next tick reads it again.
#[tokio::test(start_paused = true)]
async fn tip_restatus_waits_for_a_held_pool() {
    let mut pad = held_pool_pad().await;
    let mp = Arc::clone(&pad.mp);
    let hold = mp.template_hold();
    replace_block(&pad.q);
    pad.tip_tx
        .send(TipNotify {
            height: 0,
            header_hex: "aa".repeat(80),
            reorg_from_height: Some(0),
        })
        .unwrap();
    ping_then_null_push(&mut pad, hold).await;
    let _ = std::fs::remove_dir_all(&pad.dir);
}

/// A pool admit announced while a reorg holds the pool restatuses on the
/// next tick.
#[tokio::test(start_paused = true)]
async fn announce_restatus_waits_for_a_held_pool() {
    use bitcoin::hashes::Hash;

    let mut pad = held_pool_pad().await;
    let mp = Arc::clone(&pad.mp);
    let hold = mp.template_hold();
    replace_block(&pad.q);
    let mut sh = rbitcoin_primitives::hex_decode(&pad.sh).unwrap();
    sh.reverse();
    pad.mp
        .announce
        .send(rbitcoin_net::tx_relay::MempoolAnnounce {
            txid: bitcoin::Txid::from_byte_array([0x45; 32]),
            replaced: vec![],
            replaced_scripthashes: vec![],
            scripthashes: vec![sh.try_into().unwrap()],
        })
        .unwrap();
    ping_then_null_push(&mut pad, hold).await;
    let _ = std::fs::remove_dir_all(&pad.dir);
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
            input_count: 1,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: [0u8; 32],
            parent: rbitcoin_store::InputParent::Coinbase,
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
            input_count: 1,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: [0u8; 32],
            parent: rbitcoin_store::InputParent::Coinbase,
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

    // Header notify is written before the scripthash restatus, so it is the
    // barrier: the silence window starts after this tip handler has begun.
    let mut line = serde_json::to_string(&json!({
        "jsonrpc":"2.0","id":4,"method":"blockchain.headers.subscribe","params":[]
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
    let hdr_sub: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(hdr_sub["id"], 4, "{hdr_sub}");
    assert!(hdr_sub.get("result").is_some(), "{hdr_sub}");

    tip_tx
        .send(TipNotify {
            height: 0,
            header_hex: "bb".repeat(80),
            reorg_from_height: Some(0),
        })
        .unwrap();
    resp.clear();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        reader.read_line(&mut resp),
    )
    .await
    .expect("second tip must notify headers")
    .unwrap();
    let hdr_push: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        hdr_push["method"].as_str(),
        Some("blockchain.headers.subscribe"),
        "{hdr_push}"
    );
    resp.clear();
    let again = tokio::time::timeout(
        std::time::Duration::from_millis(400),
        reader.read_line(&mut resp),
    )
    .await;
    assert!(
        again.is_err(),
        "emptied history stays null and is not pushed again: {resp}"
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
async fn tweaks_subscribe_dones_when_the_first_wave_finishes_count() {
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
                input_count: 1,
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

    subscribe(&mut stream, "scan", 1, 1).await;
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
        "count that fits in wave 0 must done, got {done}"
    );

    drop(reader);
    subscribe(&mut stream, "scan2", 2, 1).await;
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

/// Chunk already due, heights still left: `done` with no further wave, and a
/// follow loop that was entered writes one wave and stops.
#[tokio::test]
async fn elapsed_tweaks_chunk_seals_while_heights_remain() {
    let (dir, q) = tmp_store();
    let q = std::sync::Arc::new(q);
    let chain = std::sync::Arc::new(ChainParams::mainnet());
    let started = Instant::now()
        .checked_sub(rbitcoin_electrum::tweaks::SUBSCRIBE_CHUNK)
        .expect("monotonic clock is older than one tweaks chunk");
    let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let limits = rbitcoin_electrum::tweaks::subscribe_serve_limits(false);
    let idle = Duration::from_secs(1);
    let max_line = DEFAULT_MAX_LINE_BYTES;
    let last = 3_000u32;

    let (client, server) = tokio::io::duplex(1024 * 1024);
    let (server_r, server_w) = tokio::io::split(server);
    let mut server_r = BufReader::new(server_r);
    let mut server_w = rbitcoin_electrum::server::ConnWrite::new(server_w, idle);
    let mut next = 0u32;
    tokio::time::timeout(
        Duration::from_secs(3),
        serve_tweaks_rest(
            &mut server_r,
            &mut server_w,
            &q,
            &chain,
            &peer,
            last,
            limits,
            0,
            max_line,
            started,
            &mut next,
        ),
    )
    .await
    .expect("wave-0 seal")
    .unwrap();
    drop(server_r);
    drop(server_w);
    let mut client = BufReader::new(client);
    let mut line = String::new();
    client.read_line(&mut line).await.unwrap();
    let done: Value = serde_json::from_str(&line).expect("done json");
    assert_eq!(
        done["params"][0]["message"], "done",
        "a due chunk writes done without another height wave"
    );
    line.clear();
    assert_eq!(
        client.read_line(&mut line).await.unwrap(),
        0,
        "no height line after done"
    );

    let (client, server) = tokio::io::duplex(1024 * 1024);
    let (server_r, server_w) = tokio::io::split(server);
    let mut server_r = BufReader::new(server_r);
    let mut server_w = rbitcoin_electrum::server::ConnWrite::new(server_w, idle);
    let mut next = 0u32;
    tokio::time::timeout(
        Duration::from_secs(3),
        serve_tweaks_follow_waves(
            &mut server_r,
            &mut server_w,
            &q,
            &chain,
            &peer,
            last,
            limits,
            0,
            max_line,
            started,
            &mut next,
        ),
    )
    .await
    .expect("follow seal")
    .unwrap();
    drop(server_r);
    drop(server_w);
    let mut client = BufReader::new(client);
    line.clear();
    client.read_line(&mut line).await.unwrap();
    let wave: Value = serde_json::from_str(&line).expect("wave json");
    let keys = wave["params"][0].as_object().expect("height map").len();
    assert_eq!(keys, rbitcoin_electrum::tweaks::EMPTY_WAVE_HEIGHTS as usize);
    line.clear();
    assert_eq!(
        client.read_line(&mut line).await.unwrap(),
        0,
        "a due chunk does not write the next wave"
    );

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
                input_count: 1,
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
            "failed to parse hex",
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
            "failed to parse hex digit",
        ),
        (
            "blockchain.scripthash.get_mempool",
            json!({}),
            "expected string",
        ),
        (
            "blockchain.transaction.get",
            json!(["aabb"]),
            "failed to parse hex",
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
            "invalid char, failed to create bytes from hex",
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
    assert!(
        err.contains("asof not on chain"),
        "unknown asof hash: {err}"
    );

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
        rbitcoin_electrum::server::sp_scan_ranges(0, rbitcoin_electrum::silent_scan::SP_SCAN_CHUNK),
        vec![
            (0, rbitcoin_electrum::silent_scan::SP_SCAN_CHUNK - 1),
            (
                rbitcoin_electrum::silent_scan::SP_SCAN_CHUNK,
                rbitcoin_electrum::silent_scan::SP_SCAN_CHUNK
            )
        ]
    );
    assert!(
        rbitcoin_electrum::server::sp_scan_ranges(5, 4).is_empty(),
        "a start past the tip scans nothing"
    );
    assert_eq!(
        rbitcoin_electrum::server::sp_scan_ranges(4, 4),
        vec![(4, 4)]
    );
    assert_eq!(
        rbitcoin_electrum::server::sp_scan_ranges(0, 1),
        vec![(0, 1)]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn sp_scan_stops_when_the_client_hangs_up() {
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

    struct HangUp {
        polls: std::cell::Cell<usize>,
    }
    impl AsyncRead for HangUp {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }
    impl AsyncBufRead for HangUp {
        fn poll_fill_buf(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<&[u8]>> {
            let n = self.polls.get();
            self.polls.set(n + 1);
            if n == 0 {
                Poll::Pending
            } else {
                Poll::Ready(Ok(&[]))
            }
        }
        fn consume(self: Pin<&mut Self>, _amt: usize) {}
    }

    let (_dir, q) = tmp_store();
    let q = std::sync::Arc::new(q);
    let chain = std::sync::Arc::new(ChainParams::regtest());
    let scan = "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c";
    let spend = "025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36";
    let sub = rbitcoin_electrum::silent_scan::parse_sub(
        &json!([scan, spend, 0]),
        bitcoin::Network::Regtest,
        Some(rbitcoin_electrum::silent_scan::SP_SCAN_CHUNK),
    )
    .unwrap();
    let last = rbitcoin_electrum::silent_scan::SP_SCAN_CHUNK;
    let ranges = rbitcoin_electrum::server::sp_scan_ranges(sub.start, last);
    assert_eq!(ranges.len(), 2, "the fixture spans two chunks");
    let mut reader = HangUp {
        polls: std::cell::Cell::new(0),
    };
    let scanned =
        rbitcoin_electrum::server::scan_sp_off_connection(&mut reader, &q, &chain, &sub, last)
            .await;
    assert_eq!(
        scanned.chunks, 1,
        "a hang-up before the next chunk stops the scan"
    );
}

/// A client that never reads must not hold the request. The write itself
/// returns; the connection task drops on that error.
#[tokio::test]
async fn stalled_electrum_write_is_closed() {
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::AsyncWrite;

    struct PendingWriter;
    impl AsyncWrite for PendingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Pending
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    let mut writer = PendingWriter;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        rbitcoin_electrum::server::write_line(
            &mut writer,
            json!({"jsonrpc":"2.0","id": 1, "result": null}),
            std::time::Duration::from_millis(40),
        ),
    )
    .await
    .expect("a stalled write returns before the test bound");
    let err = result.expect_err("stalled write is an error");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
}

/// A scripthash status push that the client never reads ends the connection.
/// The push is the only write after subscribe: the chain height does not move,
/// so the periodic rescan has nothing new to send.
#[tokio::test]
async fn stalled_scripthash_push_ends_the_connection() {
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    struct ScriptedRead {
        data: Vec<u8>,
        pos: usize,
    }
    impl AsyncRead for ScriptedRead {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.pos >= this.data.len() {
                return Poll::Pending;
            }
            let n = (this.data.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.data[this.pos..this.pos + n]);
            this.pos += n;
            Poll::Ready(Ok(()))
        }
    }

    struct StallWriter {
        got: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        stall: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }
    impl AsyncWrite for StallWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.stall.load(std::sync::atomic::Ordering::SeqCst) {
                return Poll::Pending;
            }
            self.got.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct Pair<R, W> {
        reader: R,
        writer: W,
    }
    impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for Pair<R, W> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
        }
    }
    impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for Pair<R, W> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().writer).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().writer).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
        }
    }

    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    rbitcoin_query::accept_and_connect_block(
        &q,
        &params,
        rbitcoin_primitives::Height::GENESIS,
        &genesis,
        rbitcoin_consensus::Milestone::NONE,
    )
    .unwrap();
    let last = 1 + params.coinbase_maturity();
    let (_tip, _time, cbs) = rbitcoin_query::pad_empty_from(
        &q,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        last,
        1,
    );
    let q = std::sync::Arc::new(q);
    let hub = std::sync::Arc::new(
        MempoolHub::open(dir.join("mempool"), std::sync::Arc::clone(&q)).unwrap(),
    );
    hub.set_relay_enabled(true);

    let sh = electrum_scripthash_hex(&[0x51]);
    let line = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"blockchain.scripthash.subscribe\",\"params\":[\"{sh}\"]}}\n"
    );
    let stall = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let stream = Pair {
        reader: ScriptedRead {
            data: line.into_bytes(),
            pos: 0,
        },
        writer: StallWriter {
            got: std::sync::Arc::clone(&got),
            stall: std::sync::Arc::clone(&stall),
        },
    };
    let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    cfg.limits.idle_timeout = std::time::Duration::from_millis(80);
    let (tip_tx, tip_rx) = tokio::sync::broadcast::channel(1);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let task = tokio::spawn(handle_client(
        stream,
        "127.0.0.1:9".parse().unwrap(),
        std::sync::Arc::clone(&q),
        std::sync::Arc::new(cfg),
        std::sync::Arc::new(params),
        tip_rx,
        Some(std::sync::Arc::clone(&hub)),
        stop,
    ));
    let _tip_tx = tip_tx;

    let mut saw_reply = false;
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let buf = got.lock().unwrap().clone();
        if String::from_utf8_lossy(&buf).contains("\"id\":1") {
            saw_reply = true;
            break;
        }
    }
    assert!(
        saw_reply,
        "subscribe reply must land before the push stalls"
    );
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    stall.store(true, std::sync::atomic::Ordering::SeqCst);

    let tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: cbs[0],
                vout: 0,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(50_0000_0000 - 10_000),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    hub.accept_tx(&tx)
        .expect("mempool spend of the subscribed script");
    let joined = tokio::time::timeout(std::time::Duration::from_secs(2), task)
        .await
        .expect("stalled push ends the connection task");
    let err = joined
        .expect("connection task")
        .expect_err("stalled push is an error");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert!(
        err.to_string().contains("write timeout"),
        "the push timeout must end the task, got {err}"
    );
    let _ = dir;
}

mod surface_tests;
