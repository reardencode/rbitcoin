use super::*;
use rbitcoin_primitives::Network;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn ctx_empty() -> (RpcContext, PathBuf) {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-rpc-meth-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    let q = Arc::new(Query::open_or_create(dir.join("store")).unwrap());
    let mp =
        MempoolHub::open_with_weight(dir.join("mempool"), Arc::clone(&q), 300_000_000).unwrap();
    mp.set_relay_enabled(true);
    let ctx = RpcContext {
        query: q,
        mempool: Some(mp),
        network: Network::Regtest,
        start: Instant::now() - Duration::from_secs(42),
        stop: Arc::new(AtomicBool::new(false)),
        connections: Arc::new(AtomicU64::new(2)),
        initial_block_download: Arc::new(AtomicBool::new(false)),
        subversion: rbitcoin_primitives::rbitcoin_subversion(
            env!("CARGO_PKG_VERSION"),
            &["testnode0"],
        )
        .unwrap(),
        regtest: None,
        peers: None,
        chain: None,
        addrman: None,
        peers_path: None,
        logpath: String::new(),
        active: std::sync::Arc::new(std::sync::Mutex::new(RpcActive::default())),
        permit_bare_multisig: true,
        alert_notify: None,
        alert_fired: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    (ctx, dir)
}

#[test]
fn help_and_getrpcinfo_list_methods() {
    let (ctx, dir) = ctx_empty();
    let help_all = dispatch(&ctx, "help", vec![]).unwrap();
    let s = help_all.as_str().unwrap();
    assert!(s.contains("getblockchaininfo"));
    assert!(s.contains("estimatesmartfee"));
    let info = dispatch(&ctx, "getrpcinfo", vec![]).unwrap();
    assert!(info["methods"].as_array().unwrap().len() >= 10);
    assert!(info["uptime"].as_u64().unwrap() >= 42);
    assert_eq!(info["active_commands"][0]["method"], json!("getrpcinfo"));
    assert!(info["active_commands"][0]["duration"].as_u64().unwrap() < 1_000_000);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn blockchain_empty_store() {
    let (ctx, dir) = ctx_empty();
    let count = dispatch(&ctx, "getblockcount", vec![]).unwrap();
    assert_eq!(count, json!(0));
    let info = dispatch(&ctx, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(info["chain"], "regtest");
    assert_eq!(info["blocks"], 0);
    assert_eq!(info["initialblockdownload"], false);
    // No headers → zero work. Empty store still has table files on disk.
    assert_eq!(info["chainwork"], "00".repeat(32));
    let store_bytes = dir_file_bytes(&dir.join("store"));
    assert!(store_bytes > 0);
    assert_eq!(info["size_on_disk"].as_u64().unwrap(), store_bytes);
    assert_eq!(info["verificationprogress"], 1.0);
    let mem = dispatch(&ctx, "getmempoolinfo", vec![]).unwrap();
    assert_eq!(mem["size"], 0);
    assert_eq!(mem["loaded"], true);
    assert_eq!(mem["permitbaremultisig"], true);
    let raw = dispatch(&ctx, "getrawmempool", vec![]).unwrap();
    assert_eq!(raw, json!([]));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getmempoolinfo_permitbaremultisig_follows_ctx() {
    let (mut ctx, dir) = ctx_empty();
    ctx.permit_bare_multisig = false;
    let mem = dispatch(&ctx, "getmempoolinfo", vec![]).unwrap();
    assert_eq!(
        mem["permitbaremultisig"], false,
        "getmempoolinfo must honor -permitbaremultisig=0"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn dir_file_bytes(root: &std::path::Path) -> u64 {
    fn walk(p: &std::path::Path, acc: &mut u64) {
        let Ok(rd) = std::fs::read_dir(p) else {
            return;
        };
        for ent in rd.flatten() {
            let path = ent.path();
            let Ok(meta) = ent.metadata() else {
                continue;
            };
            if meta.is_dir() {
                walk(&path, acc);
            } else if meta.is_file() {
                *acc = acc.saturating_add(meta.len());
            }
        }
    }
    let mut n = 0;
    walk(root, &mut n);
    n
}

#[test]
fn getblockchaininfo_disk_and_progress() {
    use bitcoin::consensus::encode::serialize;
    use rbitcoin_consensus::mine_regtest_paying;

    let (ctx, dir, hub) = ctx_regtest_hub();
    let info = dispatch(&ctx, "getblockchaininfo", vec![]).unwrap();
    let store_bytes = dir_file_bytes(&dir.join("store"));
    assert!(store_bytes > 0, "open store has table files");
    assert_eq!(
        info["size_on_disk"].as_u64().unwrap(),
        store_bytes,
        "size_on_disk is a walk of {{datadir}}/store"
    );
    assert_eq!(info["blocks"], 0);
    assert_eq!(info["headers"], 0);
    assert_eq!(info["verificationprogress"], 1.0);

    let (addr, script) = p2wpkh_regtest();
    dispatch(&ctx, "generatetoaddress", vec![json!(1), json!(addr)]).unwrap();
    let info = dispatch(&ctx, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(info["blocks"], 1);
    assert_eq!(info["headers"], 1);
    assert!(info["time"].as_u64().unwrap() > 0);
    assert!(info["mediantime"].as_u64().is_some());
    assert_eq!(info["verificationprogress"], 1.0);
    let store_bytes = dir_file_bytes(&dir.join("store"));
    assert_eq!(info["size_on_disk"].as_u64().unwrap(), store_bytes);
    assert!(store_bytes > 0);

    // IBD flag must not force the old dummy 0.5 when the tip is caught up.
    ctx.initial_block_download.store(true, Ordering::Relaxed);
    let info = dispatch(&ctx, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(info["verificationprogress"], 1.0);
    assert_eq!(info["initialblockdownload"], true);
    ctx.initial_block_download.store(false, Ordering::Relaxed);

    let prev = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time + 1;
    let child = mine_regtest_paying(prev, time, 1, script, vec![]);
    let hex = rbitcoin_primitives::hex_encode(serialize(&child));
    dispatch(&ctx, "submitheader", vec![json!(hex)]).unwrap();
    let info = dispatch(&ctx, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(info["blocks"], 1);
    assert_eq!(info["headers"], 2);
    let p = info["verificationprogress"].as_f64().unwrap();
    assert!(
        p > 0.0 && p < 1.0,
        "headers ahead of bodies → progress in (0, 1), got {p}"
    );
    assert!((p - 0.5).abs() < 1e-9, "1/2 == 0.5, got {p}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn estimatesmartfee_maps_to_product() {
    let (ctx, dir) = ctx_empty();
    let r = dispatch(&ctx, "estimatesmartfee", vec![json!(2)]).unwrap();
    // Empty mempool → negative feerate with errors.
    assert!(r["feerate"].as_f64().unwrap() < 0.0 || r.get("rbitcoin_model").is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Core `rpc_estimatefee.py`: missing/typed/mode gates + estimaterawfee.
#[test]
fn estimatesmartfee_core_param_gates() {
    let (ctx, dir) = ctx_empty();
    let e = dispatch(&ctx, "estimatesmartfee", vec![]).unwrap_err();
    assert_eq!(e["code"], ERR_MISC);
    assert!(
        e["message"].as_str().unwrap().contains("estimatesmartfee"),
        "{e}"
    );
    let e = dispatch(&ctx, "estimaterawfee", vec![]).unwrap_err();
    assert_eq!(e["code"], ERR_MISC);
    assert!(
        e["message"].as_str().unwrap().contains("estimaterawfee"),
        "{e}"
    );

    let e = dispatch(&ctx, "estimatesmartfee", vec![json!("foo")]).unwrap_err();
    assert_eq!(e["code"], ERR_TYPE_ERROR);
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .contains("JSON value of type string is not of expected type number"),
        "{e}"
    );
    let e = dispatch(&ctx, "estimatesmartfee", vec![json!(1), json!(1)]).unwrap_err();
    assert_eq!(e["code"], ERR_TYPE_ERROR);
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .contains("JSON value of type number is not of expected type string"),
        "{e}"
    );
    let e = dispatch(&ctx, "estimatesmartfee", vec![json!(1), json!("foo")]).unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .contains("Invalid estimate_mode parameter"),
        "{e}"
    );
    let e = dispatch(
        &ctx,
        "estimatesmartfee",
        vec![json!(1), json!("ECONOMICAL"), json!(1)],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_MISC);
    assert!(e["message"].as_str().unwrap().contains("estimatesmartfee"));

    for method in ["estimatesmartfee", "estimaterawfee"] {
        for bad in [json!(0), json!(1009)] {
            let e = dispatch(&ctx, method, vec![bad]).unwrap_err();
            assert_eq!(e["code"], ERR_INVALID_PARAMETER, "{method}");
            assert!(
                e["message"]
                    .as_str()
                    .unwrap()
                    .contains("Invalid conf_target, must be between 1 and 1008"),
                "{method} {e}"
            );
        }
    }

    // Valid calls must succeed (empty mempool still returns an object).
    let _ = dispatch(&ctx, "estimatesmartfee", vec![json!(1)]).unwrap();
    let _ = dispatch(
        &ctx,
        "estimatesmartfee",
        vec![json!(1), json!("ECONOMICAL")],
    )
    .unwrap();
    let _ = dispatch(&ctx, "estimatesmartfee", vec![json!(1), json!("unset")]).unwrap();
    let _ = dispatch(
        &ctx,
        "estimatesmartfee",
        vec![json!(1), json!("conservative")],
    )
    .unwrap();
    let _ = dispatch(&ctx, "estimaterawfee", vec![json!(1)]).unwrap();
    let _ = dispatch(&ctx, "estimaterawfee", vec![json!(1), json!(1)]).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mempoolinfo_loaded_and_uacomment() {
    let (ctx, dir) = ctx_empty();
    let info = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    let sub = info["subversion"].as_str().unwrap();
    assert!(sub.ends_with("(testnode0)/"), "{sub}");
    let mem = dispatch(&ctx, "getmempoolinfo", vec![]).unwrap();
    assert_eq!(mem["loaded"], true);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getnetworkinfo_localrelay_follows_mempool_relay() {
    // `p2p_blocksonly.py`: `-blocksonly` leaves relay off → localrelay false.
    let (ctx, dir) = ctx_empty();
    ctx.mempool.as_ref().unwrap().set_relay_enabled(false);
    let off = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    assert_eq!(off["localrelay"], false, "{off}");
    ctx.mempool.as_ref().unwrap().set_relay_enabled(true);
    let on = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    assert_eq!(on["localrelay"], true, "{on}");
    ctx.mempool.as_ref().unwrap().set_relay_enabled(false);
    let e = dispatch(&ctx, "sendrawtransaction", vec![json!("00")]).unwrap_err();
    let msg = e["message"].as_str().unwrap_or("");
    assert!(
        !msg.contains("relay disabled"),
        "RPC sendraw must accept while -blocksonly, got {e}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parse_wrapped_multi_sh_wsh_and_wsh() {
    let pk = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let spk = parse_wrapped_multi(&format!("sh(wsh(multi(1,{pk})))")).expect("wrapped");
    assert!(spk.is_p2sh());
    let wsh = parse_wrapped_multi(&format!("wsh(multi(1,{pk}))")).unwrap();
    assert!(wsh.is_p2wsh());
    let sh = parse_wrapped_multi(&format!("sh(multi(1,{pk}))")).unwrap();
    assert!(sh.is_p2sh());
}

#[test]
fn parse_combo_compressed_is_p2wpkh_uncompressed_p2pkh() {
    let (ctx, dir) = ctx_empty();
    let compressed = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let spk = parse_combo_descriptor(&ctx, &format!("combo({compressed})")).expect("combo");
    let want = Address::from_str("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap()
        .script_pubkey();
    assert_eq!(spk, want);
    let uncompressed = "0408ef68c46d20596cc3f6ddf7c8794f71913add807f1dc55949fa805d764d191c0b7ce6894c126fce0babc6663042f3dde9b0cf76467ea315514e5a6731149c67";
    let spk2 = parse_combo_descriptor(&ctx, &format!("combo({uncompressed})")).expect("combo unc");
    assert!(spk2.is_p2pkh());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Core `rpc_generate.py` generateblock reject strings / codes.
#[test]
fn generateblock_core_reject_shapes() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    let (ctx, dir, _hub) = ctx_regtest_hub();
    let op_true = "raw(51)";
    dispatch(
        &ctx,
        "generatetodescriptor",
        vec![json!(101), json!(op_true)],
    )
    .unwrap();

    let missing = "0000000000000000000000000000000000000000000000000000000000000000";
    let e = dispatch(
        &ctx,
        "generateblock",
        vec![json!(op_true), json!([missing])],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_ADDRESS_OR_KEY);
    assert_eq!(
        e["message"].as_str().unwrap(),
        format!("Transaction {missing} not in mempool.")
    );

    let e = dispatch(&ctx, "generateblock", vec![json!(op_true), json!(["0000"])]).unwrap_err();
    assert_eq!(e["code"], ERR_DESERIALIZATION);
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .starts_with("Transaction decode failed for 0000"),
        "{e}"
    );

    let e = dispatch(&ctx, "generateblock", vec![json!("1234"), json!([])]).unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_ADDRESS_OR_KEY);
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .contains("Invalid address or descriptor"),
        "{e}"
    );

    let ranged = "pkh(tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp/0/*)";
    let e = dispatch(&ctx, "generateblock", vec![json!(ranged), json!([])]).unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert_eq!(
        e["message"].as_str().unwrap(),
        "Ranged descriptor not accepted. Maybe pass through deriveaddresses first?"
    );

    let child_desc = "pkh(tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp/0'/0)";
    let e = dispatch(&ctx, "generateblock", vec![json!(child_desc), json!([])]).unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_ADDRESS_OR_KEY);
    assert_eq!(
        e["message"].as_str().unwrap(),
        "Cannot derive script without private keys"
    );

    let hash1 = dispatch(&ctx, "getblockhash", vec![json!(1)]).unwrap();
    let blk = dispatch(&ctx, "getblock", vec![hash1, json!(2)]).unwrap();
    let cb_txid = blk["tx"][0]["txid"].as_str().unwrap();
    let cb_val =
        (blk["tx"][0]["vout"][0]["value"].as_f64().unwrap() * 100_000_000.0).round() as u64;
    let true_spk = ScriptBuf::from_bytes(vec![0x51]);
    let parent = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(parse_hash32_display(cb_txid).unwrap()),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(cb_val - 2_000),
            script_pubkey: true_spk.clone(),
        }],
    };
    let parent_id = dispatch(
        &ctx,
        "sendrawtransaction",
        vec![json!(hex_encode(serialize(&parent)))],
    )
    .unwrap();
    let parent_txid = parent_id.as_str().unwrap().to_string();
    let child = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(cb_val - 3_000),
            script_pubkey: true_spk,
        }],
    };
    let child_hex = hex_encode(serialize(&child));
    let e = dispatch(
        &ctx,
        "generateblock",
        vec![json!(op_true), json!([child_hex, parent_txid])],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_VERIFY_ERROR);
    assert_eq!(
        e["message"].as_str().unwrap(),
        "TestBlockValidity failed: bad-txns-inputs-missingorspent"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stop_sets_flag() {
    let (ctx, dir) = ctx_empty();
    assert!(!ctx.stop.load(Ordering::SeqCst));
    dispatch(&ctx, "stop", vec![]).unwrap();
    assert!(ctx.stop.load(Ordering::SeqCst));
    let _ = std::fs::remove_dir_all(&dir);
}

/// `feature_shutdown.py`: waitfornewblock must return when stop is set.
#[test]
fn waitfornewblock_returns_on_stop() {
    use std::thread;
    use std::time::{Duration, Instant};
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let stop = Arc::clone(&ctx.stop);
    let h = thread::spawn(move || {
        thread::sleep(Duration::from_millis(30));
        stop.store(true, Ordering::SeqCst);
    });
    let t0 = Instant::now();
    let got = dispatch(&ctx, "waitfornewblock", vec![json!(5_000)]).unwrap();
    assert_eq!(got["height"], 0);
    assert!(
        t0.elapsed() < Duration::from_millis(1_000),
        "stop must wake the waiter, not the timeout"
    );
    h.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn waitforblock_and_height_return_on_stop() {
    use std::thread;
    use std::time::{Duration, Instant};
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let stop = Arc::clone(&ctx.stop);
    let h = thread::spawn(move || {
        thread::sleep(Duration::from_millis(30));
        stop.store(true, Ordering::SeqCst);
    });
    let t0 = Instant::now();
    let missing = "00".repeat(32);
    let got = dispatch(&ctx, "waitforblock", vec![json!(missing), json!(5_000)]).unwrap();
    assert_eq!(got["height"], 0);
    assert!(t0.elapsed() < Duration::from_millis(1_000));
    h.join().unwrap();

    let stop = Arc::clone(&ctx.stop);
    stop.store(false, Ordering::SeqCst);
    let h = thread::spawn(move || {
        thread::sleep(Duration::from_millis(30));
        stop.store(true, Ordering::SeqCst);
    });
    let t0 = Instant::now();
    let got = dispatch(&ctx, "waitforblockheight", vec![json!(99), json!(5_000)]).unwrap();
    assert_eq!(got["height"], 0);
    assert!(t0.elapsed() < Duration::from_millis(1_000));
    h.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unsupported_methods_error() {
    let (ctx, dir) = ctx_empty();
    let e = dispatch(&ctx, "gettxoutsetinfo", vec![]).unwrap_err();
    assert_eq!(e["code"], ERR_METHOD_NOT_FOUND);
    let e2 = dispatch(&ctx, "combinerawtransaction", vec![]).unwrap_err();
    assert_eq!(e2["code"], ERR_METHOD_NOT_FOUND);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn handle_request_roundtrip() {
    let (ctx, dir) = ctx_empty();
    let body = json!({"jsonrpc":"1.0","id":"t1","method":"getblockcount","params":[]});
    let resp = handle_request(&ctx, &body);
    assert_eq!(resp["id"], "t1");
    assert!(resp["error"].is_null());
    assert_eq!(resp["result"], 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn named_params_getblock_object() {
    let (ctx, dir) = ctx_empty();
    // Empty object is valid for methods with no args.
    let resp = handle_request(&ctx, &json!({"id":1,"method":"getblockcount","params":{}}));
    assert!(resp["error"].is_null(), "{resp}");
    assert_eq!(resp["result"], 0);

    let h = handle_request(
        &ctx,
        &json!({"method":"help","params":{"command":"getblockchaininfo"}}),
    );
    let s = h["result"].as_str().unwrap();
    assert!(s.starts_with("getblockchaininfo\n"), "{s}");

    let unknown = handle_request(
        &ctx,
        &json!({"method":"help","params":{"random":"getblockchaininfo"}}),
    );
    assert_eq!(unknown["error"]["code"], ERR_INVALID_PARAMETER);
    assert!(
        unknown["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Unknown named parameter"),
        "{unknown}"
    );

    // Named height on empty store: accepted as params (not "named not supported").
    let gh = handle_request(
        &ctx,
        &json!({"method":"getblockhash","params":{"height":0}}),
    );
    assert_ne!(
        gh["error"]["message"].as_str().unwrap_or(""),
        "named params not supported; use array"
    );
    assert_eq!(gh["error"]["code"], ERR_INVALID_PARAMETER); // height out of range

    let missing = handle_request(&ctx, &json!({"method":"getblock","params":{}}));
    assert_eq!(missing["error"]["code"], ERR_INVALID_PARAMS);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn echo_positional_named_and_mixed_args() {
    let (ctx, dir) = ctx_empty();

    let empty = handle_request(&ctx, &json!({"id":1,"method":"echo","params":[]}));
    assert!(empty["error"].is_null(), "{empty}");
    assert_eq!(empty["result"], json!([]));

    let named = handle_request(&ctx, &json!({"method":"echo","params":{"arg0":0,"arg9":9}}));
    assert!(named["error"].is_null(), "{named}");
    let mut want = vec![Value::Null; 10];
    want[0] = json!(0);
    want[9] = json!(9);
    assert_eq!(named["result"], Value::Array(want));

    let arg1 = handle_request(&ctx, &json!({"method":"echo","params":{"arg1":1}}));
    assert_eq!(arg1["result"], json!([Value::Null, 1]));

    let arg9_null = handle_request(&ctx, &json!({"method":"echo","params":{"arg9":null}}));
    assert_eq!(arg9_null["result"], json!(vec![Value::Null; 10]));

    // AuthServiceProxy mixed: echo(0, 1, arg3=3, arg5=5)
    let mixed = handle_request(
        &ctx,
        &json!({"method":"echo","params":{"args":[0,1],"arg3":3,"arg5":5}}),
    );
    assert!(mixed["error"].is_null(), "{mixed}");
    assert_eq!(
        mixed["result"],
        json!([0, 1, Value::Null, 3, Value::Null, 5])
    );

    let twice = handle_request(
        &ctx,
        &json!({"method":"echo","params":{"args":[0,1],"arg1":1}}),
    );
    assert_eq!(twice["error"]["code"], ERR_INVALID_PARAMETER);
    assert!(
        twice["error"]["message"]
            .as_str()
            .unwrap()
            .contains("specified twice"),
        "{twice}"
    );

    let twice_null = handle_request(
        &ctx,
        &json!({"method":"echo","params":{"args":[0,null,2],"arg1":1}}),
    );
    assert_eq!(twice_null["error"]["code"], ERR_INVALID_PARAMETER);

    // Mixed positional `args` must feed getblockhash(height).
    let gh = handle_request(
        &ctx,
        &json!({"method":"getblockhash","params":{"args":[0]}}),
    );
    assert_ne!(
        gh["error"]["message"].as_str().unwrap_or(""),
        "height required"
    );
    assert_eq!(gh["error"]["code"], ERR_INVALID_PARAMETER);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hash_hex_display_matches_blockhash_display_and_reverses_parse() {
    // Fixed non-palindrome internal bytes.
    let mut internal = [0u8; 32];
    for (i, b) in internal.iter_mut().enumerate() {
        *b = i as u8;
    }
    let disp = hash_hex_display(&internal);
    let via_type = bitcoin::BlockHash::from_byte_array(internal).to_string();
    assert_eq!(disp, via_type);
    let back = parse_hash32_display(&disp).unwrap();
    assert_eq!(back, internal);
    // Raw internal hex is not equal to display.
    assert_ne!(disp, rbitcoin_primitives::hex_encode(internal));
}

#[test]
fn all_methods_callable_empty_or_error() {
    let (ctx, dir) = ctx_empty();
    // Control / network always succeed on empty store.
    for m in [
        "uptime",
        "syncwithvalidationinterfacequeue",
        "getnetworkinfo",
        "getconnectioncount",
        "getpeerinfo",
        "ping",
        "getmempoolinfo",
        "getrawmempool",
    ] {
        let _ = dispatch(&ctx, m, vec![]).expect(m);
    }
    // Empty store: no tip → difficulty errors.
    let _ = dispatch(&ctx, "getdifficulty", vec![]);
    let _ = dispatch(&ctx, "getrawmempool", vec![json!(true)]).unwrap();
    let _ = dispatch(&ctx, "help", vec![json!("estimatesmartfee")]).unwrap();
    let _ = dispatch(&ctx, "help", vec![json!("getblockchaininfo")]).unwrap();
    let _ = dispatch(&ctx, "help", vec![json!("help")]).unwrap();
    let _ = dispatch(&ctx, "help", vec![json!("unknown_method_xyz")]).unwrap();
    // Expected errors (missing params / missing blocks).
    for (m, params) in [
        ("getblockhash", vec![]),
        ("getblockhash", vec![json!(99)]),
        ("getbestblockhash", vec![]),
        ("getblockheader", vec![]),
        ("getblockheader", vec![json!("00".repeat(32))]),
        ("getblock", vec![]),
        ("getblock", vec![json!("00".repeat(32))]),
        ("getrawtransaction", vec![]),
        ("getrawtransaction", vec![json!("00".repeat(32))]),
        ("getmempoolentry", vec![]),
        ("getmempoolentry", vec![json!("00".repeat(32))]),
        ("sendrawtransaction", vec![]),
        ("sendrawtransaction", vec![json!("00")]),
        ("testmempoolaccept", vec![]),
        ("decoderawtransaction", vec![]),
        ("nosuchmethod", vec![]),
        ("getblocktemplate", vec![]),
        ("combinerawtransaction", vec![]),
        ("generatetoaddress", vec![]),
        ("gettxoutsetinfo", vec![]),
    ] {
        let _ = dispatch(&ctx, m, &params);
    }
    let e = dispatch(&ctx, "decodescript", vec![json!("51")]).unwrap_err();
    assert_eq!(e["code"], ERR_METHOD_NOT_FOUND);
    // estimatesmartfee requires conf_target (rpc_estimatefee.py)
    let _ = dispatch(&ctx, "estimatesmartfee", vec![]).unwrap_err();
    let _ = dispatch(&ctx, "estimatesmartfee", vec![json!(6)]).unwrap();
    // handle_request error shapes
    let _ = handle_request(&ctx, &json!({}));
    let _ = handle_request(&ctx, &json!({"method":"getblockcount","params":{}}));
    let _ = handle_request(&ctx, &json!({"method":"getblockcount","params":1}));
    let _ = handle_request(&ctx, &json!({"id":1,"method":"nosuch","params":[]}));
    // no mempool
    let ctx2 = RpcContext {
        query: Arc::clone(&ctx.query),
        mempool: None,
        network: Network::Regtest,
        start: Instant::now(),
        stop: Arc::new(AtomicBool::new(false)),
        connections: Arc::new(AtomicU64::new(0)),
        initial_block_download: Arc::new(AtomicBool::new(true)),
        subversion: rbitcoin_primitives::rbitcoin_subversion(
            env!("CARGO_PKG_VERSION"),
            &[] as &[&str],
        )
        .unwrap(),
        regtest: None,
        peers: None,
        chain: None,
        addrman: None,
        peers_path: None,
        logpath: String::new(),
        active: std::sync::Arc::new(std::sync::Mutex::new(RpcActive::default())),
        permit_bare_multisig: true,
        alert_notify: None,
        alert_fired: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let mem2 = dispatch(&ctx2, "getmempoolinfo", vec![]).unwrap();
    assert_eq!(mem2["loaded"], true);
    let _ = dispatch(&ctx2, "getrawmempool", vec![json!(true)]).unwrap();
    let _ = dispatch(&ctx2, "estimatesmartfee", vec![json!(1)]).unwrap();
    let _ = dispatch(&ctx2, "sendrawtransaction", vec![json!("00")]);
    let info = dispatch(&ctx2, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(info["initialblockdownload"], true);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn chain_methods_against_mined_regtest() {
    use bitcoin::consensus::encode::serialize_hex;
    use rbitcoin_consensus::ChainParams;
    use rbitcoin_test::build_mature_regtest_with_spend;

    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-rpc-chain-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    let q = Arc::new(Query::open_or_create(dir.join("store")).unwrap());
    let params = ChainParams::for_network(Network::Regtest);
    let chain = build_mature_regtest_with_spend(&q, &params);
    let mp =
        MempoolHub::open_with_weight(dir.join("mempool"), Arc::clone(&q), 300_000_000).unwrap();
    mp.set_relay_enabled(true);
    let ctx = RpcContext {
        query: Arc::clone(&q),
        mempool: Some(mp.clone()),
        network: Network::Regtest,
        start: Instant::now(),
        stop: Arc::new(AtomicBool::new(false)),
        connections: Arc::new(AtomicU64::new(1)),
        initial_block_download: Arc::new(AtomicBool::new(false)),
        subversion: rbitcoin_primitives::rbitcoin_subversion(
            env!("CARGO_PKG_VERSION"),
            &[] as &[&str],
        )
        .unwrap(),
        regtest: None,
        peers: None,
        chain: None,
        addrman: None,
        peers_path: None,
        logpath: String::new(),
        active: std::sync::Arc::new(std::sync::Mutex::new(RpcActive::default())),
        permit_bare_multisig: true,
        alert_notify: None,
        alert_fired: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };

    let tip_h = chain.tip_height();
    let count = dispatch(&ctx, "getblockcount", vec![]).unwrap();
    assert_eq!(count.as_u64().unwrap(), tip_h as u64);

    // Pin: getbestblockhash matches rust-bitcoin BlockHash Display (Core order).
    let tip_hash = chain.tip_hash();
    let tip_display = tip_hash.to_string();
    let internal = tip_hash.to_byte_array();
    assert_ne!(
        tip_display,
        rbitcoin_primitives::hex_encode(internal),
        "regtest tip Display must differ from raw internal hex (non-palindrome)"
    );
    assert_eq!(
        tip_display,
        hash_hex_display(&internal),
        "hash_hex_display must match BlockHash Display"
    );

    let best = dispatch(&ctx, "getbestblockhash", vec![]).unwrap();
    let best_s = best.as_str().unwrap().to_string();
    assert_eq!(
        best_s, tip_display,
        "getbestblockhash must be Core/display order, not internal"
    );
    let hash = dispatch(&ctx, "getblockhash", vec![json!(tip_h)]).unwrap();
    assert_eq!(hash.as_str().unwrap(), best_s);
    // Lookup must accept display-order hex from Core clients.
    let hdr = dispatch(&ctx, "getblockheader", vec![json!(best_s.clone())]).unwrap();
    assert_eq!(hdr["height"], tip_h);
    assert_eq!(hdr["hash"], best_s);
    // Merkleroot field must also be display order (consistent with hash).
    let mr = hdr["merkleroot"].as_str().unwrap();
    assert_eq!(mr.len(), 64);
    assert_eq!(mr, hash_hex_display(&parse_hash32_display(mr).unwrap()));
    let hdr_hex = dispatch(
        &ctx,
        "getblockheader",
        vec![json!(best_s.clone()), json!(false)],
    )
    .unwrap();
    assert!(hdr_hex.as_str().unwrap().len() > 10);
    for verb in [0u64, 1, 2] {
        let blk = dispatch(&ctx, "getblock", vec![json!(best_s.clone()), json!(verb)]).unwrap();
        if verb == 0 {
            assert!(blk.as_str().unwrap().len() > 20);
        } else {
            assert_eq!(blk["height"], tip_h);
            assert_eq!(blk["hash"], best_s);
            assert!(blk["tx"].as_array().unwrap().len() >= 1);
        }
    }
    let _ = dispatch(&ctx, "getdifficulty", vec![]).unwrap();
    let info = dispatch(&ctx, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(info["blocks"], tip_h);
    assert_eq!(info["bestblockhash"], best_s);

    // Coinbase of tip for getrawtransaction — use Txid Display (Core order).
    let fks = q.block_tx_fks(rbitcoin_primitives::Height(tip_h)).unwrap();
    let tx = q.reconstruct_tx(fks[0]).unwrap();
    let txid_display = tx.compute_txid().to_string();
    let txid_internal = tx.compute_txid().to_byte_array();
    assert_eq!(txid_display, hash_hex_display(&txid_internal));
    // Internal-order hex must NOT be accepted as a Core-form getrawtransaction id
    // when it differs from display (typical for real txids).
    let internal_hex = rbitcoin_primitives::hex_encode(txid_internal);
    if internal_hex != txid_display {
        let miss = dispatch(&ctx, "getrawtransaction", vec![json!(internal_hex)]);
        assert!(
            miss.is_err(),
            "internal-order hex must not resolve as Core display txid"
        );
    }
    let raw = dispatch(&ctx, "getrawtransaction", vec![json!(txid_display.clone())]).unwrap();
    assert!(raw.as_str().unwrap().len() > 20);
    let verbose = dispatch(
        &ctx,
        "getrawtransaction",
        vec![json!(txid_display.clone()), json!(true)],
    )
    .unwrap();
    assert_eq!(verbose["txid"], txid_display);

    let hex = serialize_hex(&tx);
    assert_eq!(verbose["txid"], txid_display);

    // testmempoolaccept dry path (may reject coinbase — still exercises code)
    let _ = dispatch(&ctx, "testmempoolaccept", vec![json!([hex.clone()])]);
    let _ = dispatch(&ctx, "sendrawtransaction", vec![json!(hex)]);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Single-txid mempool RPC must not scan/clone the live set.
#[test]
fn mempool_txid_lookups_do_not_list_live() {
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
    use rbitcoin_primitives::Height;

    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }
    let (ctx, dir) = ctx_empty();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(
        &ctx.query,
        &params,
        Height::GENESIS,
        &genesis,
        Milestone::NONE,
    )
    .unwrap();
    const N_SPENDS: u32 = 3;
    let (_tip, _tip_time, coinbase_txids) = rbitcoin_consensus::pad_empty_from(
        &ctx.query,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        100 + N_SPENDS,
        N_SPENDS,
    );
    let mp = ctx.mempool.as_ref().expect("mempool");
    mp.set_relay_enabled(true);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let mut live = Vec::new();
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
        mp.accept_tx(&tx).expect("accept");
        live.push(tx);
    }
    let want = live[1].compute_txid();
    let want_hex = hash_hex_display(&want.to_byte_array());
    let _ = mp.sample_reset_perf();

    let entry = dispatch(&ctx, "getmempoolentry", vec![json!(want_hex.clone())]).unwrap();
    assert!(entry["weight"].as_u64().unwrap() > 0);
    let raw = dispatch(&ctx, "getrawtransaction", vec![json!(want_hex.clone())]).unwrap();
    assert!(raw.as_str().unwrap().len() > 20);
    let verb = dispatch(
        &ctx,
        "getrawtransaction",
        vec![json!(want_hex), json!(true)],
    )
    .unwrap();
    assert_eq!(verb["txid"], format!("{want}"));

    let s = mp.sample_reset_perf();
    assert_eq!(s.list_live, 0, "getrawtransaction must not list_live");
    assert_eq!(
        s.list_live_meta, 0,
        "getmempoolentry must not list_live_meta"
    );

    let miss = dispatch(&ctx, "getmempoolentry", vec![json!("00".repeat(32))]).unwrap_err();
    assert_eq!(miss["message"], "Transaction not in mempool");
    let miss_raw = dispatch(&ctx, "getrawtransaction", vec![json!("11".repeat(32))]).unwrap_err();
    assert_eq!(
        miss_raw["message"],
        "No such mempool or blockchain transaction"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Graph fields come from the cluster, not stub 1/0. Local sendraw is
/// unbroadcast until a peer getdata completes.
#[test]
fn mempool_graph_fields_follow_cluster_and_unbroadcast() {
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
    use rbitcoin_primitives::Height;

    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }
    let (ctx, dir) = ctx_empty();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(
        &ctx.query,
        &params,
        Height::GENESIS,
        &genesis,
        Milestone::NONE,
    )
    .unwrap();
    let (_tip, _tip_time, coinbase_txids) = rbitcoin_consensus::pad_empty_from(
        &ctx.query,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        102,
        2,
    );
    let mp = ctx.mempool.as_ref().expect("mempool");
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
    mp.accept_tx(&parent).expect("parent");
    let child = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 1_000 - 2_000),
            script_pubkey: spk.clone(),
        }],
    };
    mp.accept_tx(&child).expect("child");

    let parent_hex = hash_hex_display(&parent.compute_txid().to_byte_array());
    let child_hex = hash_hex_display(&child.compute_txid().to_byte_array());
    let parent_entry = dispatch(&ctx, "getmempoolentry", vec![json!(parent_hex.clone())]).unwrap();
    let child_entry = dispatch(&ctx, "getmempoolentry", vec![json!(child_hex.clone())]).unwrap();
    assert_eq!(parent_entry["ancestorcount"], 1);
    assert_eq!(parent_entry["descendantcount"], 2);
    assert_eq!(child_entry["ancestorcount"], 2);
    assert_eq!(child_entry["descendantcount"], 1);
    assert_eq!(parent_entry["unbroadcast"], false);
    assert_eq!(child_entry["unbroadcast"], false);
    assert_eq!(parent_entry["depends"], json!([]));
    assert_eq!(parent_entry["spentby"], json!([child_hex.clone()]));
    assert_eq!(child_entry["depends"], json!([parent_hex.clone()]));
    assert_eq!(child_entry["spentby"], json!([]));

    let verbose = dispatch(&ctx, "getrawmempool", vec![json!(true)]).unwrap();
    assert_eq!(verbose[&child_hex]["ancestorcount"], 2);
    assert_eq!(verbose[&parent_hex]["descendantcount"], 2);
    assert_eq!(verbose[&child_hex]["depends"], json!([parent_hex.clone()]));
    assert_eq!(verbose[&parent_hex]["spentby"], json!([child_hex.clone()]));

    let info = dispatch(&ctx, "getmempoolinfo", vec![]).unwrap();
    assert_eq!(
        info["unbroadcastcount"], 0,
        "P2P-style accept is not a local unbroadcast"
    );

    let local = Transaction {
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
            value: Amount::from_sat(50_0000_0000 - 3_000),
            script_pubkey: spk,
        }],
    };
    let local_hex_tx = serialize_hex(&local);
    let sent = dispatch(&ctx, "sendrawtransaction", vec![json!(local_hex_tx)]).unwrap();
    let local_hex = hash_hex_display(&local.compute_txid().to_byte_array());
    assert_eq!(sent, json!(local_hex.clone()));

    let info = dispatch(&ctx, "getmempoolinfo", vec![]).unwrap();
    assert_eq!(info["unbroadcastcount"], 1);
    let local_entry = dispatch(&ctx, "getmempoolentry", vec![json!(local_hex.clone())]).unwrap();
    assert_eq!(local_entry["unbroadcast"], true);
    assert_eq!(local_entry["ancestorcount"], 1);

    mp.mark_broadcast(&local.compute_txid());
    let info = dispatch(&ctx, "getmempoolinfo", vec![]).unwrap();
    assert_eq!(
        info["unbroadcastcount"], 0,
        "getdata/serve must clear unbroadcast"
    );
    let local_entry = dispatch(&ctx, "getmempoolentry", vec![json!(local_hex)]).unwrap();
    assert_eq!(local_entry["unbroadcast"], false);

    let _ = mp.sample_reset_perf();
    let _ = dispatch(&ctx, "getmempoolentry", vec![json!(child_hex)]).unwrap();
    let s = mp.sample_reset_perf();
    assert_eq!(s.list_live_meta, 0, "graph fields must not list_live_meta");

    let _ = std::fs::remove_dir_all(&dir);
}

struct TestMiner(Arc<rbitcoin_net::ChainHub>);

impl RpcRegtest for TestMiner {
    fn generate_to_script(
        &self,
        nblocks: u32,
        script_pubkey: ScriptBuf,
        extra_txs: Vec<Transaction>,
    ) -> Result<Vec<BlockHash>, String> {
        self.0
            .generate_to_script(nblocks, script_pubkey, extra_txs)
            .map_err(|e| e.to_string())
    }

    fn assemble_block_to_script(
        &self,
        script_pubkey: ScriptBuf,
        extra_txs: Vec<Transaction>,
    ) -> Result<Block, String> {
        self.0
            .assemble_block_to_script(script_pubkey, extra_txs)
            .map_err(|e| e.to_string())
    }

    fn submit_block(&self, block: Block) -> SubmitBlockOutcome {
        use bitcoin::Target;
        let hash = block.block_hash();
        if self.0.is_block_invalid(&hash) {
            return SubmitBlockOutcome::Rejected("duplicate-invalid".into());
        }
        let target = Target::from_compact(block.header.bits);
        if block.header.validate_pow(target).is_err() {
            return SubmitBlockOutcome::Rejected("high-hash".into());
        }
        let prev = block.header.prev_blockhash.to_byte_array();
        let known = self
            .0
            .query
            .get_header_by_hash(&prev)
            .ok()
            .flatten()
            .is_some()
            || self
                .0
                .held_body(&BlockHash::from_byte_array(prev))
                .is_some();
        if !known {
            return SubmitBlockOutcome::Rejected("prev-blk-not-found".into());
        }
        match self.0.accept_received_block(block.clone()) {
            Ok(rbitcoin_net::AcceptOutcome::Accepted { .. }) => SubmitBlockOutcome::Accepted,
            Ok(rbitcoin_net::AcceptOutcome::AlreadyHave) => SubmitBlockOutcome::Duplicate,
            Ok(rbitcoin_net::AcceptOutcome::IgnoredWeaker) => SubmitBlockOutcome::IgnoredWeaker,
            Err(e) => {
                let s = e.to_string();
                let s = s.strip_prefix("consensus: ").unwrap_or(s.as_str());
                let s = s.strip_prefix("protocol: ").unwrap_or(s);
                let mapped = if s.contains("unknown parent")
                    || s.contains("BadPrev")
                    || s.contains("unexpected previous")
                {
                    "prev-blk-not-found".to_string()
                } else if s.contains("pow invalid")
                    || s.contains("InvalidPow")
                    || s.contains("high-hash")
                {
                    "high-hash".to_string()
                } else {
                    [
                        "bad-txns-nonfinal",
                        "bad-txns-duplicate",
                        "bad-txns-inputs-missingorspent",
                        "bad-txns-in-belowout",
                        "bad-cb-missing",
                        "bad-blk-length",
                        "bad-diffbits",
                        "time-too-old",
                        "time-too-new",
                        "bad-txnmrklroot",
                    ]
                    .into_iter()
                    .find(|n| s.contains(n))
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| s.to_string())
                };
                if mapped != "bad-txnmrklroot"
                    && mapped != "high-hash"
                    && mapped != "prev-blk-not-found"
                {
                    self.0.note_invalid_block(hash);
                    let _ = self.0.ensure_header(&block.header);
                }
                SubmitBlockOutcome::Rejected(mapped)
            }
        }
    }

    fn set_mock_time(&self, timestamp: i64) -> Result<(), String> {
        self.0.clock.set_mock(timestamp);
        Ok(())
    }
}

fn ctx_regtest_hub() -> (RpcContext, PathBuf, Arc<rbitcoin_net::ChainHub>) {
    use rbitcoin_consensus::{ChainParams, Milestone};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-rpc-gen-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    let hub = Arc::new(rbitcoin_net::ChainHub::new(
        Query::open_or_create(dir.join("store")).unwrap(),
        ChainParams::regtest(),
        Milestone::NONE,
    ));
    hub.ensure_genesis().unwrap();
    let mp =
        MempoolHub::open_with_weight(dir.join("mempool"), hub.query.clone(), 300_000_000).unwrap();
    mp.set_relay_enabled(true);
    let ctx = RpcContext {
        query: hub.query.clone(),
        mempool: Some(mp),
        network: Network::Regtest,
        start: Instant::now(),
        stop: Arc::new(AtomicBool::new(false)),
        connections: Arc::new(AtomicU64::new(0)),
        initial_block_download: Arc::new(AtomicBool::new(false)),
        subversion: rbitcoin_primitives::rbitcoin_subversion(
            env!("CARGO_PKG_VERSION"),
            &[] as &[&str],
        )
        .unwrap(),
        regtest: Some(Arc::new(TestMiner(Arc::clone(&hub)))),
        peers: None,
        chain: Some(Arc::clone(&hub)),
        addrman: None,
        peers_path: None,
        logpath: String::new(),
        active: std::sync::Arc::new(std::sync::Mutex::new(RpcActive::default())),
        permit_bare_multisig: true,
        alert_notify: None,
        alert_fired: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    (ctx, dir, hub)
}

fn p2wpkh_regtest() -> (String, ScriptBuf) {
    use bitcoin::hashes::Hash;
    use bitcoin::{Address, WPubkeyHash};
    let wpkh = WPubkeyHash::from_byte_array([0x75; 20]);
    let script = ScriptBuf::new_p2wpkh(&wpkh);
    let addr = Address::from_script(&script, BtcNetwork::Regtest)
        .expect("p2wpkh script is a valid address");
    (addr.to_string(), script)
}

#[test]
fn generate_refuses_on_mainnet() {
    let (mut ctx, dir, _hub) = ctx_regtest_hub();
    ctx.network = Network::Mainnet;
    let (addr, _) = p2wpkh_regtest();
    for m in [
        "generatetoaddress",
        "generateblock",
        "generate",
        "submitblock",
        "setmocktime",
    ] {
        let e = match m {
            "generatetoaddress" => dispatch(&ctx, m, vec![json!(1), json!(addr.clone())]),
            "generateblock" => dispatch(&ctx, m, vec![json!(addr.clone()), json!([])]),
            "generate" => dispatch(&ctx, m, vec![json!(1)]),
            "setmocktime" => dispatch(&ctx, m, vec![json!(1)]),
            _ => dispatch(&ctx, m, vec![json!("00")]),
        }
        .unwrap_err();
        let msg = e["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("regtest only"),
            "{m} must refuse on mainnet: {e}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn generate_one_to_p2wpkh() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let (addr, script) = p2wpkh_regtest();
    let hashes = dispatch(&ctx, "generatetoaddress", vec![json!(1), json!(addr)]).unwrap();
    let arr = hashes.as_array().expect("hash array");
    assert_eq!(arr.len(), 1);
    assert_eq!(dispatch(&ctx, "getblockcount", vec![]).unwrap(), json!(1));
    let best = dispatch(&ctx, "getbestblockhash", vec![]).unwrap();
    assert_eq!(best, arr[0]);
    let blk = dispatch(&ctx, "getblock", vec![best.clone(), json!(2)]).unwrap();
    let hex = blk["tx"][0]["vout"][0]["scriptPubKey"]["hex"]
        .as_str()
        .unwrap();
    assert_eq!(hex, rbitcoin_primitives::hex_encode(script.as_bytes()));
    assert_eq!(
        blk["tx"][0]["vout"][0]["scriptPubKey"]["address"],
        json!(addr)
    );
    // Core getblock(hash, False) is verbosity 0 (raw hex).
    let raw = dispatch(&ctx, "getblock", vec![best.clone(), json!(false)]).unwrap();
    assert!(raw.as_str().unwrap().len() > 160);
    let cb_txid = blk["tx"][0]["txid"].as_str().unwrap();
    let raw_tx = dispatch(&ctx, "getrawtransaction", vec![json!(cb_txid), json!(0)]).unwrap();
    assert!(raw_tx.as_str().unwrap().len() > 20);
    // Core third arg is a blockhash; we always have Class A — ignore it.
    let same = dispatch(
        &ctx,
        "getrawtransaction",
        vec![json!(cb_txid), json!(0), json!(best)],
    )
    .unwrap();
    assert_eq!(same, raw_tx);
    let net = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    assert_eq!(net["connections_in"], 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getblock_verbosity_1_txids_skip_reconstruct() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let hashes = dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let best = hashes.as_array().unwrap()[0].clone();
    rbitcoin_store::reset_tx_full_gets();
    let v1 = dispatch(&ctx, "getblock", vec![best.clone(), json!(1)]).unwrap();
    assert!(
        rbitcoin_store::tx_full_gets().is_empty(),
        "verbosity 1 must not zip inwit: {:?}",
        rbitcoin_store::tx_full_gets()
    );
    let txs = v1["tx"].as_array().unwrap();
    assert_eq!(txs.len(), 1);
    assert!(txs[0].as_str().unwrap().len() == 64);
    let v2 = dispatch(&ctx, "getblock", vec![best, json!(2)]).unwrap();
    assert!(v2["tx"][0]["vin"][0].get("txid").is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn generateblock_submit_false_returns_hex_without_connecting() {
    let (ctx, dir, hub) = ctx_regtest_hub();
    let tip_before = hub.tip_height();
    let mut named = serde_json::Map::new();
    named.insert("output".into(), json!("raw(55)"));
    named.insert("transactions".into(), json!([]));
    named.insert("submit".into(), json!(false));
    let got = dispatch(&ctx, "generateblock", RpcParams::named(named)).unwrap();
    assert!(got.get("hex").and_then(|v| v.as_str()).is_some());
    assert!(got.get("hash").and_then(|v| v.as_str()).is_some());
    assert_eq!(hub.tip_height(), tip_before);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn miniwallet_raw_scan_and_gettxout() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let desc = "raw(51)";
    let hashes = dispatch(&ctx, "generatetodescriptor", vec![json!(2), json!(desc)]).unwrap();
    assert_eq!(hashes.as_array().unwrap().len(), 2);
    assert_eq!(dispatch(&ctx, "getblockcount", vec![]).unwrap(), json!(2));

    rbitcoin_store::reset_tx_full_gets();
    let scan = dispatch(&ctx, "scantxoutset", vec![json!("start"), json!([desc])]).unwrap();
    assert!(
        rbitcoin_store::tx_full_gets().is_empty(),
        "scantxoutset shindex must not zip inwit: {:?}",
        rbitcoin_store::tx_full_gets()
    );
    assert_eq!(scan["success"], true);
    assert_eq!(scan["height"], 2);
    let uns = scan["unspents"].as_array().unwrap();
    assert_eq!(uns.len(), 2, "two generated OP_TRUE coinbases: {scan}");
    assert!(uns.iter().all(|u| u["coinbase"] == true));

    let txid = uns[1]["txid"].as_str().unwrap();
    let utxo = dispatch(&ctx, "gettxout", vec![json!(txid), json!(0)]).unwrap();
    assert!(utxo["confirmations"].as_u64().unwrap() >= 1);
    assert_eq!(utxo["coinbase"], true);
    assert_eq!(utxo["scriptPubKey"]["hex"], "51");

    let tips = dispatch(&ctx, "getchaintips", vec![]).unwrap();
    assert_eq!(tips[0]["status"], "active");
    assert_eq!(tips[0]["height"], 2);

    let waited = dispatch(&ctx, "waitforblockheight", vec![json!(2), json!(100)]).unwrap();
    assert_eq!(waited["height"], 2);

    let idx = dispatch(&ctx, "getindexinfo", vec![]).unwrap();
    assert_eq!(idx["txindex"]["synced"], true);
    assert_eq!(idx["txindex"]["best_block_height"], 2);
    let only = dispatch(&ctx, "getindexinfo", vec![json!("txindex")]).unwrap();
    assert_eq!(only["txindex"]["synced"], true);
    let empty = dispatch(&ctx, "getindexinfo", vec![json!("coinstatsindex")]).unwrap();
    assert_eq!(empty, json!({}));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scantxoutset_txout_fallback_without_shindex() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    ctx.query.set_sh_index_enabled(false);
    let desc = "raw(51)";
    dispatch(&ctx, "generatetodescriptor", vec![json!(2), json!(desc)]).unwrap();
    let scan = dispatch(&ctx, "scantxoutset", vec![json!("start"), json!([desc])]).unwrap();
    assert_eq!(scan["success"], true);
    assert_eq!(scan["unspents"].as_array().unwrap().len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn generate_includes_mempool_and_maps_immature() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    let (ctx, dir, _hub) = ctx_regtest_hub();
    dispatch(&ctx, "generate", vec![json!(101)]).unwrap();
    assert_eq!(dispatch(&ctx, "getblockcount", vec![]).unwrap(), json!(101));

    let hash1 = dispatch(&ctx, "getblockhash", vec![json!(1)]).unwrap();
    let blk = dispatch(&ctx, "getblock", vec![hash1, json!(2)]).unwrap();
    let cb_txid = blk["tx"][0]["txid"].as_str().unwrap();
    let cb_val =
        (blk["tx"][0]["vout"][0]["value"].as_f64().unwrap() * 100_000_000.0).round() as u64;

    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(parse_hash32_display(cb_txid).unwrap()),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(cb_val - 1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let hex = hex_encode(serialize(&spend));
    let tid = dispatch(&ctx, "sendrawtransaction", vec![json!(hex)]).unwrap();
    let pool = dispatch(&ctx, "getrawmempool", vec![]).unwrap();
    assert_eq!(pool, json!([tid]));

    dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let empty = dispatch(&ctx, "getrawmempool", vec![]).unwrap();
    assert_eq!(empty, json!([]));
    let tip = dispatch(&ctx, "getbestblockhash", vec![]).unwrap();
    let mined = dispatch(&ctx, "getblock", vec![tip, json!(1)]).unwrap();
    assert_eq!(mined["tx"].as_array().unwrap().len(), 2);
    let parent = dispatch(
        &ctx,
        "getblockhash",
        vec![json!(mined["height"].as_u64().unwrap() - 1)],
    )
    .unwrap();
    assert_eq!(mined["previousblockhash"], parent);

    let scan = dispatch(
        &ctx,
        "scantxoutset",
        vec![json!("start"), json!(["raw(51)"])],
    )
    .unwrap();
    let uns = scan["unspents"].as_array().unwrap();
    assert!(
        uns.iter().all(|u| u["txid"] != json!(cb_txid)),
        "spent coinbase must drop from scan: {scan}"
    );
    assert!(uns.iter().any(|u| u["coinbase"] == false));

    // At tip 102, coinbase N is mempool-mature when 102 >= N+99 → N<=3.
    let hash2 = dispatch(&ctx, "getblockhash", vec![json!(10)]).unwrap();
    let blk2 = dispatch(&ctx, "getblock", vec![hash2, json!(2)]).unwrap();
    let immature_txid = blk2["tx"][0]["txid"].as_str().unwrap();
    let immature_val =
        (blk2["tx"][0]["vout"][0]["value"].as_f64().unwrap() * 100_000_000.0).round() as u64;
    let bad = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(parse_hash32_display(immature_txid).unwrap()),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(immature_val - 1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let e = dispatch(
        &ctx,
        "sendrawtransaction",
        vec![json!(hex_encode(serialize(&bad)))],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_VERIFY_REJECTED);
    assert_eq!(e["message"], "bad-txns-premature-spend-of-coinbase");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn generate_selects_chained_mempool_parent_first() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    let (ctx, dir, _hub) = ctx_regtest_hub();
    dispatch(&ctx, "generate", vec![json!(101)]).unwrap();
    let hash1 = dispatch(&ctx, "getblockhash", vec![json!(1)]).unwrap();
    let blk = dispatch(&ctx, "getblock", vec![hash1, json!(2)]).unwrap();
    let cb_txid = blk["tx"][0]["txid"].as_str().unwrap();
    let cb_val =
        (blk["tx"][0]["vout"][0]["value"].as_f64().unwrap() * 100_000_000.0).round() as u64;

    let parent = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(parse_hash32_display(cb_txid).unwrap()),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(cb_val - 2_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let parent_hex = hex_encode(serialize(&parent));
    let parent_id = dispatch(&ctx, "sendrawtransaction", vec![json!(parent_hex)]).unwrap();
    let child = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(cb_val - 3_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let child_id = dispatch(
        &ctx,
        "sendrawtransaction",
        vec![json!(hex_encode(serialize(&child)))],
    )
    .unwrap();
    dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let tip = dispatch(&ctx, "getbestblockhash", vec![]).unwrap();
    let mined = dispatch(&ctx, "getblock", vec![tip, json!(1)]).unwrap();
    let txids = mined["tx"].as_array().unwrap();
    assert_eq!(txids.len(), 3, "coinbase + parent + child: {mined}");
    assert_eq!(txids[1], parent_id);
    assert_eq!(txids[2], child_id);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getblocktemplate_requires_segwit_and_shapes_empty_and_one_tx() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let e = dispatch(&ctx, "getblocktemplate", vec![json!({})]).unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert!(e["message"].as_str().unwrap().contains("segwit rule"));
    dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let tmpl = dispatch(&ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    assert_eq!(tmpl["height"], 2);
    assert_eq!(tmpl["version"], 0x2000_0000 | (1 << 28));
    assert!(tmpl["transactions"].as_array().unwrap().is_empty());
    let info = dispatch(&ctx, "getmininginfo", vec![]).unwrap();
    assert_eq!(info["blocks"], 1);
    assert_eq!(info["pooledtx"], 0);
    let min_fee = info["blockmintxfee"].as_f64().expect("blockmintxfee");
    assert!((min_fee - 1e-8).abs() < 1e-15, "blockmintxfee={min_fee}");

    dispatch(&ctx, "generate", vec![json!(100)]).unwrap();
    let hash1 = dispatch(&ctx, "getblockhash", vec![json!(1)]).unwrap();
    let blk = dispatch(&ctx, "getblock", vec![hash1, json!(2)]).unwrap();
    let cb_txid = blk["tx"][0]["txid"].as_str().unwrap();
    let cb_val =
        (blk["tx"][0]["vout"][0]["value"].as_f64().unwrap() * 100_000_000.0).round() as u64;
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(parse_hash32_display(cb_txid).unwrap()),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(cb_val - 1_000),
            // OP_CHECKSIG: Core GBT sigops = 1 * WITNESS_SCALE_FACTOR.
            script_pubkey: ScriptBuf::from_bytes(vec![0xac]),
        }],
    };
    let tid = dispatch(
        &ctx,
        "sendrawtransaction",
        vec![json!(hex_encode(serialize(&spend)))],
    )
    .unwrap();
    let tmpl = dispatch(&ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    let txs = tmpl["transactions"].as_array().unwrap();
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0]["txid"], tid);
    assert_eq!(txs[0]["sigops"], 4);
    let lp1 = tmpl["longpollid"].as_str().unwrap().to_string();
    let tmpl2 = dispatch(&ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    assert_eq!(tmpl2["longpollid"], lp1);
    let stale = dispatch(
        &ctx,
        "getblocktemplate",
        vec![json!({"rules": ["segwit"], "longpollid": "not-this-id"})],
    )
    .unwrap();
    assert_eq!(stale["longpollid"], lp1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getblocktemplate_proposal_core_needles() {
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::consensus::encode::serialize;
    use bitcoin::{CompactTarget, TxMerkleNode};
    let (ctx, dir, hub) = ctx_regtest_hub();
    dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let tip = dispatch(&ctx, "getbestblockhash", vec![]).unwrap();
    let tip_s = tip.as_str().unwrap();
    let blk = dispatch(&ctx, "getblock", vec![json!(tip_s), json!(0)]).unwrap();
    let raw = hex_decode(blk.as_str().unwrap()).unwrap();
    let mined: Block = deserialize(&raw).unwrap();
    let coinbase = mined.txdata[0].clone();
    let bits = mined.header.bits;
    let mut next = Block {
        header: Header {
            version: BlockVersion::from_consensus(0x2000_0000),
            prev_blockhash: mined.block_hash(),
            merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
            time: mined.header.time.saturating_add(1),
            bits,
            nonce: 0,
        },
        txdata: vec![coinbase.clone()],
    };
    next.header.merkle_root = next.compute_merkle_root().unwrap();
    let hex = hex_encode(serialize(&next));
    let req = json!({"mode": "proposal", "data": hex, "rules": ["segwit"]});
    let r = dispatch(&ctx, "getblocktemplate", vec![req]).unwrap();
    assert!(r.is_null(), "valid proposal: {r}");

    let mut bad_cb = next.clone();
    bad_cb.txdata[0].input[0].previous_output.txid = Txid::from_byte_array([1u8; 32]);
    let r = dispatch(
        &ctx,
        "getblocktemplate",
        vec![json!({
            "mode": "proposal",
            "data": hex_encode(serialize(&bad_cb)),
            "rules": ["segwit"]
        })],
    )
    .unwrap();
    assert_eq!(r, json!("bad-cb-missing"), "{r}");

    let mut empty = next.clone();
    empty.txdata.clear();
    empty.header.merkle_root = TxMerkleNode::from_byte_array([0u8; 32]);
    let r = dispatch(
        &ctx,
        "getblocktemplate",
        vec![json!({
            "mode": "proposal",
            "data": hex_encode(serialize(&empty)),
            "rules": ["segwit"]
        })],
    )
    .unwrap();
    assert_eq!(r, json!("bad-blk-length"), "{r}");

    let mut bits_bad = next.clone();
    bits_bad.header.bits = CompactTarget::from_consensus(469762303);
    let r = dispatch(
        &ctx,
        "getblocktemplate",
        vec![json!({
            "mode": "proposal",
            "data": hex_encode(serialize(&bits_bad)),
            "rules": ["segwit"]
        })],
    )
    .unwrap();
    assert_eq!(r, json!("bad-diffbits"), "{r}");

    let mut old = next.clone();
    old.header.time = 0;
    let r = dispatch(
        &ctx,
        "getblocktemplate",
        vec![json!({
            "mode": "proposal",
            "data": hex_encode(serialize(&old)),
            "rules": ["segwit"]
        })],
    )
    .unwrap();
    assert_eq!(r, json!("time-too-old"), "{r}");

    let _ = hub.tip_height();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn prioritisetransaction_dummy_and_deprioritise_skips_generate() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let e = dispatch(
        &ctx,
        "prioritisetransaction",
        vec![json!("11".repeat(32)), json!(1), json!(0)],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert!(e["message"]
        .as_str()
        .unwrap()
        .contains("Priority is no longer supported"));

    dispatch(&ctx, "generate", vec![json!(101)]).unwrap();
    let hash1 = dispatch(&ctx, "getblockhash", vec![json!(1)]).unwrap();
    let blk = dispatch(&ctx, "getblock", vec![hash1, json!(2)]).unwrap();
    let cb_txid = blk["tx"][0]["txid"].as_str().unwrap();
    let cb_val =
        (blk["tx"][0]["vout"][0]["value"].as_f64().unwrap() * 100_000_000.0).round() as u64;
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(parse_hash32_display(cb_txid).unwrap()),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(cb_val - 1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let tid = dispatch(
        &ctx,
        "sendrawtransaction",
        vec![json!(hex_encode(serialize(&spend)))],
    )
    .unwrap();
    let fee = 1_000i64;
    dispatch(
        &ctx,
        "prioritisetransaction",
        vec![tid.clone(), json!(0), json!(-fee)],
    )
    .unwrap();
    let pri = dispatch(&ctx, "getprioritisedtransactions", vec![]).unwrap();
    assert_eq!(pri[tid.as_str().unwrap()]["fee_delta"], -fee);
    assert_eq!(pri[tid.as_str().unwrap()]["in_mempool"], true);
    dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let pool = dispatch(&ctx, "getrawmempool", vec![]).unwrap();
    assert_eq!(pool, json!([tid]), "deprioritised tx must stay unmined");

    let missing = dispatch(&ctx, "prioritisetransaction", vec![]).unwrap_err();
    assert_eq!(missing["code"], ERR_MISC);
    assert_eq!(missing["message"], "prioritisetransaction");
    let extra = dispatch(&ctx, "getprioritisedtransactions", vec![json!(true)]).unwrap_err();
    assert_eq!(extra["code"], ERR_MISC);

    let entry = dispatch(&ctx, "getmempoolentry", vec![tid.clone()]).unwrap();
    assert!(entry["fees"]["chunk"].is_number());
    assert_eq!(entry["chunkweight"], entry["weight"]);
    let cluster = dispatch(&ctx, "getmempoolcluster", vec![tid.clone()]).unwrap();
    assert_eq!(cluster["txcount"], 1);
    assert_eq!(cluster["chunks"][0]["txs"], json!([tid]));
    let missing_cl = dispatch(&ctx, "getmempoolcluster", vec![json!("11".repeat(32))]).unwrap_err();
    assert_eq!(missing_cl["code"], ERR_INVALID_ADDRESS_OR_KEY);
    let ancs = dispatch(&ctx, "getmempoolancestors", vec![tid.clone()]).unwrap();
    assert_eq!(ancs, json!([]));
    let desc = dispatch(&ctx, "getmempooldescendants", vec![tid.clone()]).unwrap();
    assert_eq!(desc, json!([]));
    let diagram = dispatch(&ctx, "getmempoolfeeratediagram", vec![]).unwrap();
    // This test deprioritises the only live tx (modified fee ≤ 0), so the
    // diagram may be empty — still a JSON array.
    assert!(diagram.is_array(), "{diagram}");
    let spend = dispatch(
        &ctx,
        "gettxspendingprevout",
        vec![json!([{ "txid": cb_txid, "vout": 0 }])],
    )
    .unwrap();
    assert_eq!(spend[0]["spendingtxid"], tid);
    let info = dispatch(&ctx, "getmempoolinfo", vec![]).unwrap();
    assert_eq!(info["optimal"], true);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn submitblock_good_and_bad_merkle() {
    use bitcoin::consensus::encode::serialize;
    use rbitcoin_consensus::mine_regtest_paying;

    let (ctx, dir, hub) = ctx_regtest_hub();
    let (_, script) = p2wpkh_regtest();
    let prev = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time + 1;
    let good = mine_regtest_paying(prev, time, 1, script.clone(), vec![]);
    let good_hex = rbitcoin_primitives::hex_encode(serialize(&good));
    let r = dispatch(&ctx, "submitblock", vec![json!(good_hex)]).unwrap();
    assert!(r.is_null(), "good submitblock: {r}");
    assert_eq!(dispatch(&ctx, "getblockcount", vec![]).unwrap(), json!(1));

    let prev2 = hub.tip_hash().unwrap();
    let time2 = hub.tip_header().unwrap().time + 1;
    let mut bad = mine_regtest_paying(prev2, time2, 2, script, vec![]);
    bad.header.merkle_root = bitcoin::TxMerkleNode::from_byte_array([0xab; 32]);
    // Re-grind so we fail on merkle, not PoW.
    let target = bitcoin::Target::from_compact(bad.header.bits);
    for nonce in 0..u32::MAX {
        bad.header.nonce = nonce;
        if bad.header.validate_pow(target).is_ok() {
            break;
        }
    }
    let bad_hex = rbitcoin_primitives::hex_encode(serialize(&bad));
    let r = dispatch(&ctx, "submitblock", vec![json!(bad_hex)]).unwrap();
    assert!(!r.is_null(), "bad merkle must not be accepted: {r}");
    let msg = r.as_str().unwrap_or("");
    assert!(
        msg.to_ascii_lowercase().contains("merkle")
            || msg.contains("consensus")
            || msg.contains("bad"),
        "bad merkle reject: {r}"
    );
    assert_eq!(dispatch(&ctx, "getblockcount", vec![]).unwrap(), json!(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn invalidate_reconsider_tip() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let (addr, _) = p2wpkh_regtest();
    dispatch(&ctx, "generatetoaddress", vec![json!(3), json!(addr)]).unwrap();
    assert_eq!(dispatch(&ctx, "getblockcount", vec![]).unwrap(), json!(3));
    let tip = dispatch(&ctx, "getbestblockhash", vec![])
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    dispatch(&ctx, "invalidateblock", vec![json!(tip.clone())]).unwrap();
    assert_eq!(dispatch(&ctx, "getblockcount", vec![]).unwrap(), json!(2));
    dispatch(&ctx, "reconsiderblock", vec![json!(tip)]).unwrap();
    assert_eq!(dispatch(&ctx, "getblockcount", vec![]).unwrap(), json!(3));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn block_min_fee_matches_core_getfee() {
    // 200 vB paying 1 sat meets 1 sat/kvB (1e3 >= 200) and any zero floor.
    assert!(meets_block_min_feerate(1, 800, 1));
    assert!(meets_block_min_feerate(1, 800, 0));
    // 250 vB at 1000 sat/kvB needs 250 sat.
    assert!(meets_block_min_feerate(250, 1000, 1000));
    assert!(!meets_block_min_feerate(249, 1000, 1000));
    // 40 sat/kvB on 111 vB (5 sat) must not meet a 50 sat/kvB floor.
    assert!(!meets_block_min_feerate(5, 444, 50));
}

#[test]
fn submitheader_decode_and_prev_needles() {
    use bitcoin::consensus::encode::serialize;

    let (ctx, dir, hub) = ctx_regtest_hub();
    let bad_hex = "xx".repeat(80);
    let e = dispatch(&ctx, "submitheader", vec![json!(bad_hex)]).unwrap_err();
    assert_eq!(e["code"], ERR_DESERIALIZATION);
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .contains("Block header decode failed"),
        "{e}"
    );
    let short = "ff".repeat(78);
    let e = dispatch(&ctx, "submitheader", vec![json!(short)]).unwrap_err();
    assert_eq!(e["code"], ERR_DESERIALIZATION);
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .contains("Block header decode failed"),
        "{e}"
    );

    let orphan = serialize(&bitcoin::block::Header {
        version: bitcoin::block::Version::from_consensus(4),
        prev_blockhash: bitcoin::BlockHash::from_byte_array([0x12; 32]),
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([0; 32]),
        time: 1,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    });
    let e = dispatch(
        &ctx,
        "submitheader",
        vec![json!(rbitcoin_primitives::hex_encode(orphan))],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_VERIFY_ERROR);
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .contains("Must submit previous header"),
        "{e}"
    );

    let (addr, _) = p2wpkh_regtest();
    dispatch(&ctx, "generatetoaddress", vec![json!(3), json!(addr)]).unwrap();
    let tip = hub.tip_hash().unwrap();
    let mut old = hub.tip_header().unwrap();
    old.prev_blockhash = tip;
    old.time = 1;
    let e = dispatch(
        &ctx,
        "submitheader",
        vec![json!(rbitcoin_primitives::hex_encode(serialize(&old)))],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_VERIFY_ERROR);
    assert!(
        e["message"].as_str().unwrap().contains("time-too-old"),
        "{e}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn submitheader_invalid_parent_keeps_one_header_tip() {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::Amount;
    use rbitcoin_consensus::mine_regtest_paying;

    let (ctx, dir, hub) = ctx_regtest_hub();
    let (_, script) = p2wpkh_regtest();
    let prev = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time + 1;
    let mut parent = mine_regtest_paying(prev, time, 1, script.clone(), vec![]);
    // Too-large coinbase → submitblock rejects after headers are known.
    parent.txdata[0].output[0].value = Amount::from_sat(100 * 100_000_000);
    parent.header.merkle_root = parent.compute_merkle_root().unwrap();
    let target = bitcoin::Target::from_compact(parent.header.bits);
    for nonce in 0..u32::MAX {
        parent.header.nonce = nonce;
        if parent.header.validate_pow(target).is_ok() {
            break;
        }
    }
    let child = mine_regtest_paying(parent.block_hash(), time + 1, 2, script, vec![]);
    dispatch(
        &ctx,
        "submitheader",
        vec![json!(rbitcoin_primitives::hex_encode(serialize(
            &parent.header
        )))],
    )
    .unwrap();
    dispatch(
        &ctx,
        "submitheader",
        vec![json!(rbitcoin_primitives::hex_encode(serialize(
            &child.header
        )))],
    )
    .unwrap();
    let before = dispatch(&ctx, "getchaintips", vec![]).unwrap();
    let n_before = before.as_array().unwrap().len();
    dispatch(
        &ctx,
        "submitblock",
        vec![json!(rbitcoin_primitives::hex_encode(serialize(&parent)))],
    )
    .unwrap();
    let tips = dispatch(&ctx, "getchaintips", vec![]).unwrap();
    assert_eq!(
        tips.as_array().unwrap().len(),
        n_before,
        "rejecting the parent body must not add a second tip: {tips}"
    );
    assert!(
        tips.as_array()
            .unwrap()
            .iter()
            .any(|t| t["status"] == "invalid"),
        "{tips}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn submitheader_child_is_headers_only() {
    use bitcoin::consensus::encode::serialize;
    use rbitcoin_consensus::mine_regtest_paying;

    let (ctx, dir, hub) = ctx_regtest_hub();
    let (_, script) = p2wpkh_regtest();
    let prev = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time + 1;
    let child = mine_regtest_paying(prev, time, 1, script, vec![]);
    let hex = rbitcoin_primitives::hex_encode(serialize(&child));
    let r = dispatch(&ctx, "submitheader", vec![json!(hex)]).unwrap();
    assert!(r.is_null(), "{r}");
    let info = dispatch(&ctx, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(info["blocks"], 0);
    assert_eq!(info["headers"], 1);
    let tips = dispatch(&ctx, "getchaintips", vec![]).unwrap();
    let arr = tips.as_array().unwrap();
    assert!(
        arr.iter()
            .any(|t| t["status"] == "headers-only" && t["height"] == 1),
        "{tips}"
    );
    let miss = dispatch(&ctx, "invalidateblock", vec![json!("00".repeat(32))]).unwrap_err();
    assert_eq!(miss["code"], ERR_INVALID_ADDRESS_OR_KEY);
    assert_eq!(miss["message"], "Block not found");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mockscheduler_rebroadcasts_unbroadcast() {
    let (ctx, dir) = ctx_empty();
    let e = dispatch(&ctx, "mockscheduler", vec![]).unwrap_err();
    assert!(
        e["message"]
            .as_str()
            .unwrap_or("")
            .contains("delta_seconds"),
        "{e}"
    );
    let r = dispatch(&ctx, "mockscheduler", vec![json!(900)]).unwrap();
    assert!(r.is_null(), "{r}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn setmocktime_negative_is_invalid_parameter() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let e = dispatch(&ctx, "setmocktime", vec![json!(-1)]).unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .contains("Mocktime must be in the range [0, 9223372036], not -1."),
        "{e}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Buried deployments from ChainParams. No invented BIP9.
#[test]
fn getdeploymentinfo_buried_from_params() {
    let (ctx, dir, hub) = ctx_regtest_hub();
    let info = dispatch(&ctx, "getdeploymentinfo", vec![]).unwrap();
    assert_eq!(info["height"], 0);
    let d = &info["deployments"];
    assert_eq!(d["csv"]["type"], "buried");
    assert_eq!(d["csv"]["height"], hub.params.csv_height());
    // Next block is height 1 ≥ csv@1 → already active for the next block.
    assert_eq!(d["csv"]["active"], true);
    assert_eq!(d["segwit"]["type"], "buried");
    assert_eq!(d["segwit"]["height"], hub.params.segwit_height());
    assert_eq!(d["segwit"]["active"], true, "regtest segwit height 0");
    assert!(d.get("testdummy").is_none(), "no invented BIP9");

    let (addr, _) = p2wpkh_regtest();
    dispatch(&ctx, "generatetoaddress", vec![json!(1), json!(addr)]).unwrap();
    let info = dispatch(&ctx, "getdeploymentinfo", vec![]).unwrap();
    assert_eq!(info["height"], 1);
    assert_eq!(info["deployments"]["csv"]["active"], true);
    assert_eq!(info["deployments"]["bip65"]["active"], true);
    assert_eq!(info["deployments"]["bip66"]["active"], true);
    assert_eq!(info["deployments"]["bip34"]["active"], false);

    let mut over = rbitcoin_consensus::ChainParams::regtest();
    over.apply_test_activation_height("csv", 102).unwrap();
    let d = buried_deployments(&over, 100);
    assert_eq!(d["csv"]["height"], 102);
    assert_eq!(d["csv"]["active"], false, "next block 101 < 102");
    assert_eq!(
        buried_deployments(&over, 101)["csv"]["active"],
        true,
        "next block 102 ≥ 102"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn setmocktime_generate_uses_mock() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let mock = 1_600_000_000u64;
    dispatch(&ctx, "setmocktime", vec![json!(mock)]).unwrap();
    let (addr, _) = p2wpkh_regtest();
    dispatch(&ctx, "generatetoaddress", vec![json!(1), json!(addr)]).unwrap();
    let best = dispatch(&ctx, "getbestblockhash", vec![]).unwrap();
    let hdr = dispatch(&ctx, "getblockheader", vec![best]).unwrap();
    let t = hdr["time"].as_u64().unwrap();
    assert!(
        t >= mock && t < mock + 600,
        "generate time {t} should honor mock {mock}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn setmocktime_future_header_uses_mock() {
    use bitcoin::consensus::encode::serialize;
    use rbitcoin_consensus::mine_regtest_paying;

    let (ctx, dir, hub) = ctx_regtest_hub();
    let mock = 1_600_000_000u64;
    dispatch(&ctx, "setmocktime", vec![json!(mock)]).unwrap();
    let (_, script) = p2wpkh_regtest();
    let prev = hub.tip_hash().unwrap();
    let far = (mock + 3 * 3600) as u32;
    let far_block = mine_regtest_paying(prev, far, 1, script, vec![]);
    let hex = rbitcoin_primitives::hex_encode(serialize(&far_block));
    let r = dispatch(&ctx, "submitblock", vec![json!(hex)]).unwrap();
    let msg = r.as_str().unwrap_or("");
    assert!(
        msg.contains("future") || msg.contains("timestamp") || msg.contains("time-too-new"),
        "future header vs mock now: {r}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getblockheader_chainwork_is_real_regtest_work() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let gen = dispatch(&ctx, "getblockhash", vec![json!(0)]).unwrap();
    let hdr0 = dispatch(&ctx, "getblockheader", vec![gen]).unwrap();
    let w0 = hdr0["chainwork"].as_str().unwrap();
    assert_eq!(w0.len(), 64);
    assert_eq!(&w0[62..], "02", "genesis work is 2: {w0}");
    dispatch(&ctx, "generate", vec![json!(50)]).unwrap();
    let best = dispatch(&ctx, "getbestblockhash", vec![]).unwrap();
    let hdr = dispatch(&ctx, "getblockheader", vec![best]).unwrap();
    let w = hdr["chainwork"].as_str().unwrap();
    // 51 headers (0..=50) × 2 = 102 = 0x66
    assert_eq!(&w[62..], "66", "tip work {w}");
    let info = dispatch(&ctx, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(info["chainwork"], hdr["chainwork"]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getblockstats_coinbase_only_and_op_return_match_helper() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    let (ctx, dir, hub) = ctx_regtest_hub();
    dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let got = dispatch(&ctx, "getblockstats", vec![json!(1)]).unwrap();
    let block = hub.query.reconstruct_block_at_height(Height(1)).unwrap();
    let want = crate::blockstats::compute_block_stats(
        1,
        &block,
        rbitcoin_consensus::median_time_past(hub.query.as_ref(), Height(1))
            .unwrap_or(block.header.time),
        rbitcoin_consensus::block_subsidy(1, &hub.params),
        |op| {
            for tx in &block.txdata {
                if tx.compute_txid() == op.txid {
                    return tx.output.get(op.vout as usize).cloned();
                }
            }
            None
        },
    )
    .unwrap();
    assert_eq!(got, want.to_json());
    assert_eq!(got["txs"], 1);
    assert_eq!(got["ins"], 0);
    assert_eq!(got["subsidy"], 50_0000_0000u64);
    assert_eq!(got["totalfee"], 0);

    let genesis = dispatch(&ctx, "getblockstats", vec![json!(0)]).unwrap();
    assert_eq!(
        genesis["blockhash"],
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    );
    assert_eq!(genesis["utxo_increase"], 1);
    assert_eq!(genesis["utxo_size_inc"], 117);
    assert_eq!(genesis["utxo_increase_actual"], 0);
    assert_eq!(genesis["utxo_size_inc_actual"], 0);

    dispatch(&ctx, "generate", vec![json!(100)]).unwrap();
    let h1 = dispatch(&ctx, "getblockhash", vec![json!(1)]).unwrap();
    let blk = dispatch(&ctx, "getblock", vec![h1, json!(2)]).unwrap();
    let cb_txid = blk["tx"][0]["txid"].as_str().unwrap();
    let cb_val =
        (blk["tx"][0]["vout"][0]["value"].as_f64().unwrap() * 100_000_000.0).round() as u64;
    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(parse_hash32_display(cb_txid).unwrap()),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(cb_val - 2_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x21]),
            },
        ],
    };
    dispatch(
        &ctx,
        "sendrawtransaction",
        vec![json!(hex_encode(serialize(&spend)))],
    )
    .unwrap();
    dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let tip_hash = dispatch(&ctx, "getbestblockhash", vec![]).unwrap();
    rbitcoin_store::reset_tx_full_gets();
    let v1 = dispatch(&ctx, "getblock", vec![tip_hash.clone(), json!(1)]).unwrap();
    assert!(
        rbitcoin_store::tx_full_gets().is_empty(),
        "verbosity 1 2-tx block: {:?}",
        rbitcoin_store::tx_full_gets()
    );
    let v1txs = v1["tx"].as_array().unwrap();
    assert_eq!(v1txs.len(), 2);
    assert!(v1txs
        .iter()
        .all(|t| t.as_str().is_some_and(|s| s.len() == 64)));
    let v2 = dispatch(&ctx, "getblock", vec![tip_hash, json!(2)]).unwrap();
    assert!(v2["tx"][1]["vin"][0].get("txid").is_some());
    let tip_h = dispatch(&ctx, "getblockcount", vec![]).unwrap();
    let got = dispatch(&ctx, "getblockstats", vec![tip_h.clone()]).unwrap();
    let h = tip_h.as_u64().unwrap() as u32;
    let block = hub.query.reconstruct_block_at_height(Height(h)).unwrap();
    let want = crate::blockstats::compute_block_stats(
        h,
        &block,
        rbitcoin_consensus::median_time_past(hub.query.as_ref(), Height(h))
            .unwrap_or(block.header.time),
        rbitcoin_consensus::block_subsidy(h, &hub.params),
        |op| {
            for tx in &block.txdata {
                if tx.compute_txid() == op.txid {
                    return tx.output.get(op.vout as usize).cloned();
                }
            }
            let (fk, _rec) = hub.query.get_tx_by_txid(&op.txid.to_byte_array()).ok()??;
            let out = hub.query.tx_output_at_fk(fk, op.vout).ok()?;
            Some(TxOut {
                value: Amount::from_sat(out.value.max(0) as u64),
                script_pubkey: ScriptBuf::from_bytes(out.script),
            })
        },
    )
    .unwrap();
    assert_eq!(got, want.to_json());
    assert_eq!(got["txs"], 2);
    assert_eq!(got["ins"], 1);
    assert!(
        got["utxo_increase_actual"].as_i64().unwrap() < got["utxo_increase"].as_i64().unwrap(),
        "OP_RETURN excluded from actual: {got}"
    );
    assert_eq!(got["totalfee"], 2_000);

    let mut named = serde_json::Map::new();
    named.insert("hash_or_height".into(), got["blockhash"].clone());
    let by_hash = dispatch(&ctx, "getblockstats", RpcParams::named(named)).unwrap();
    assert_eq!(by_hash, got);
    let mut named = serde_json::Map::new();
    named.insert("hash_or_height".into(), json!(h));
    named.insert("stats".into(), json!(["minfee"]));
    let one = dispatch(&ctx, "getblockstats", RpcParams::named(named)).unwrap();
    assert_eq!(
        one.as_object().unwrap().keys().collect::<Vec<_>>(),
        vec!["minfee"]
    );
    assert_eq!(one["minfee"], got["minfee"]);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getblockstats_core_error_needles() {
    use bitcoin::consensus::encode::serialize;
    use rbitcoin_consensus::mine_regtest_paying;

    let (ctx, dir, hub) = ctx_regtest_hub();
    dispatch(&ctx, "generate", vec![json!(1)]).unwrap();

    let e = dispatch(&ctx, "getblockstats", vec![json!(2)]).unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .contains("Target block height 2 after current tip 1"),
        "{e}"
    );
    let e = dispatch(&ctx, "getblockstats", vec![json!(-1)]).unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .contains("Target block height -1 is negative"),
        "{e}"
    );
    let e = dispatch(&ctx, "getblockstats", vec![json!(1), json!(["asdfghjkl"])]).unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert_eq!(e["message"], "Invalid selected statistic 'asdfghjkl'");
    let e = dispatch(
        &ctx,
        "getblockstats",
        vec![json!(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        )],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_ADDRESS_OR_KEY);
    assert_eq!(e["message"], "Block not found");
    let e = dispatch(&ctx, "getblockstats", vec![]).unwrap_err();
    assert_eq!(e["code"], ERR_MISC);
    assert_eq!(e["message"], "getblockstats hash_or_height ( stats )");
    let e = dispatch(&ctx, "getblockstats", vec![json!("00"), json!(1), json!(2)]).unwrap_err();
    assert_eq!(e["code"], ERR_MISC);
    assert_eq!(e["message"], "getblockstats hash_or_height ( stats )");

    let (_, script) = p2wpkh_regtest();
    let prev = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time + 1;
    let child = mine_regtest_paying(prev, time, 2, script, vec![]);
    let hex = rbitcoin_primitives::hex_encode(serialize(&child));
    dispatch(&ctx, "submitheader", vec![json!(hex)]).unwrap();
    let e = dispatch(
        &ctx,
        "getblockstats",
        vec![json!(child.block_hash().to_string())],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_MISC);
    assert_eq!(e["message"], "Block not available (not fully downloaded)");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn testmempoolaccept_script_reject_maps_dersig_and_details() {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    let err = "script: script verification failed: SIG_DER";
    let reason = accept_reject_reason(&err);
    assert_eq!(
        reason,
        "mempool-script-verify-flag-failed (Non-canonical DER signature)"
    );
    let prev = Txid::from_byte_array([0x11; 32]);
    let tx = Transaction {
        version: TxVersion::TWO,
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
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let details = accept_reject_details(&err, &tx).expect("script reject has details");
    let want = format!(
        "{reason}, input 0 of {} (wtxid {}), spending {}:0",
        tx.compute_txid(),
        tx.compute_wtxid(),
        prev
    );
    assert_eq!(details, want);
}

#[test]
fn testmempoolaccept_script_reject_maps_cltv_parens() {
    for (token, paren) in [
        (
            "stack empty",
            "Operation not valid with the current stack size",
        ),
        ("CLTV negative", "Negative locktime"),
        ("CLTV type", "Locktime requirement not satisfied"),
        ("CLTV", "Locktime requirement not satisfied"),
        ("CLTV final sequence", "Locktime requirement not satisfied"),
    ] {
        let err = format!("script: script verification failed: {token}");
        assert_eq!(
            accept_reject_reason(&err),
            format!("mempool-script-verify-flag-failed ({paren})")
        );
    }
}

#[test]
fn getpeerinfo_empty_without_hub() {
    let (ctx, dir) = ctx_empty();
    let r = dispatch(&ctx, "getpeerinfo", vec![]).unwrap();
    assert_eq!(r, json!([]));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getpeerinfo_lists_registered_session() {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use rbitcoin_net::{PeerConnType, PeerHub};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let (mut ctx, dir) = ctx_empty();
    let hub = PeerHub::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445);
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::P2P_V2,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&bind, ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:0.1.0(testnode0)/".into(),
        start_height: 0,
        relay: true,
    };
    let live = hub.register(addr, bind, &ver, false, PeerConnType::OutboundFullRelay);
    live.note_recv("pong", 8);
    ctx.peers = Some(hub.clone());
    let r = dispatch(&ctx, "getpeerinfo", vec![]).unwrap();
    let arr = r.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["subver"], "/rbitcoin:0.1.0(testnode0)/");
    assert_eq!(arr[0]["inbound"], false);
    assert_eq!(arr[0]["relaytxes"], true);
    assert_eq!(arr[0]["permissions"], json!([]));
    hub.set_relay_perm(true);
    let r = dispatch(&ctx, "getpeerinfo", vec![]).unwrap();
    assert_eq!(r.as_array().unwrap()[0]["permissions"], json!(["relay"]));
    assert_eq!(arr[0]["addr"], "127.0.0.1:18444");
    assert_eq!(arr[0]["last_block"], 0);
    assert_eq!(arr[0]["last_transaction"], 0);
    assert!(arr[0].get("minfeefilter").is_some());
    assert!(arr[0]["bytesrecv_per_msg"]["pong"].as_u64().unwrap() >= 29);
    let net = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    assert_eq!(net["connections_in"], 0);
    assert_eq!(net["connections_out"], 1);
    assert_eq!(net["connections"], 1);
    let totals = dispatch(&ctx, "getnettotals", vec![]).unwrap();
    assert!(totals["totalbytesrecv"].as_u64().unwrap() >= 29);
    assert_eq!(totals["totalbytessent"].as_u64().unwrap(), 0);

    // p2p_invalid_messages.py:96 — a 12-byte header fragment must bump
    // totalbytesrecv before the frame is complete.
    let wire = rbitcoin_net::WireBytes::new();
    live.attach_wire(wire.clone());
    let before = dispatch(&ctx, "getnettotals", vec![]).unwrap()["totalbytesrecv"]
        .as_u64()
        .unwrap();
    wire.recv
        .fetch_add(12, std::sync::atomic::Ordering::Relaxed);
    let mid = dispatch(&ctx, "getnettotals", vec![]).unwrap()["totalbytesrecv"]
        .as_u64()
        .unwrap();
    assert_eq!(mid, before + 12);

    // rpc_net.py:100 — dual inbound+outbound is two connections, not
    // outbound-follow-only (ctx.connections stays 0 here).
    let inbound = hub.register(bind, addr, &ver, true, PeerConnType::Inbound);
    assert_eq!(
        dispatch(&ctx, "getconnectioncount", vec![]).unwrap(),
        json!(2)
    );
    drop(inbound);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn addnode_and_disconnectnode_on_table() {
    use rbitcoin_net::PeerHub;
    let (mut ctx, dir) = ctx_empty();
    let hub = PeerHub::new();
    ctx.peers = Some(hub);
    let e = dispatch(&ctx, "addnode", vec![json!("127.0.0.1:1"), json!("onetry")]).unwrap_err();
    assert!(e["message"].as_str().unwrap().contains("dialer"), "{e}");
    let e = dispatch(&ctx, "disconnectnode", vec![json!("127.0.0.1:1")]).unwrap_err();
    assert_eq!(e["code"], ERR_CLIENT_NODE_NOT_CONNECTED);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn addpeeraddress_adds_to_addrman_and_saves_peers() {
    use rbitcoin_net::AddrMan;
    use std::sync::Mutex;

    let (mut ctx, dir) = ctx_empty();
    let peers_path = dir.join("peers");
    let am = Arc::new(Mutex::new(AddrMan::new()));
    ctx.addrman = Some(Arc::clone(&am));
    ctx.peers_path = Some(peers_path.clone());

    let out = dispatch(
        &ctx,
        "addpeeraddress",
        vec![json!("128.1.2.3"), json!(8333)],
    )
    .unwrap();
    assert_eq!(out, json!({"success": true}));
    {
        let g = am.lock().unwrap();
        assert_eq!(g.len(), 1);
        assert!(g.peers().contains(&"128.1.2.3:8333".parse().unwrap()));
    }
    let loaded = AddrMan::load(&peers_path).unwrap();
    assert_eq!(loaded.len(), 1);
    assert!(loaded.peers().contains(&"128.1.2.3:8333".parse().unwrap()));

    let named = RpcParams::named(
        json!({"address": "129.0.0.1", "port": 8334, "tried": false})
            .as_object()
            .unwrap()
            .clone(),
    );
    let out = dispatch(&ctx, "addpeeraddress", named).unwrap();
    assert_eq!(out, json!({"success": true}));
    assert_eq!(am.lock().unwrap().len(), 2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn addnode_two_nodes_see_each_other() {
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_net::P2PNode;
    use rbitcoin_query::Query;

    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-rpc-2n-{n}"));
    std::fs::create_dir_all(dir.join("a")).unwrap();
    std::fs::create_dir_all(dir.join("b")).unwrap();
    let qa = Query::open_or_create(dir.join("a/store")).unwrap();
    let qb = Query::open_or_create(dir.join("b/store")).unwrap();
    let params = ChainParams::regtest();
    let na = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qa,
        params.clone(),
        Milestone::NONE,
        "/rbitcoin:0.1.0(testnode0)/".into(),
        rbitcoin_net::DEFAULT_MAX_INBOUND,
    )
    .await
    .unwrap();
    let nb = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qb,
        params,
        Milestone::NONE,
        "/rbitcoin:0.1.0(testnode1)/".into(),
        rbitcoin_net::DEFAULT_MAX_INBOUND,
    )
    .await
    .unwrap();
    let (mut ctx_a, _d0) = ctx_empty();
    ctx_a.peers = Some(Arc::clone(&na.peers));
    let (mut ctx_b, _d1) = ctx_empty();
    ctx_b.peers = Some(Arc::clone(&nb.peers));
    let baddr = nb.local_addr.to_string();
    dispatch(&ctx_a, "addnode", vec![json!(baddr), json!("onetry")]).unwrap();
    let mut saw = false;
    for _ in 0..80 {
        let pa = dispatch(&ctx_a, "getpeerinfo", vec![]).unwrap();
        let pb = dispatch(&ctx_b, "getpeerinfo", vec![]).unwrap();
        let a_ok = pa.as_array().is_some_and(|a| {
            a.iter()
                .any(|p| p["subver"] == "/rbitcoin:0.1.0(testnode1)/" && p["inbound"] == false)
        });
        let b_ok = pb.as_array().is_some_and(|a| {
            a.iter()
                .any(|p| p["subver"] == "/rbitcoin:0.1.0(testnode0)/" && p["inbound"] == true)
        });
        if a_ok && b_ok {
            saw = true;
            let pong = pa[0]["bytesrecv_per_msg"]["pong"].as_u64().unwrap_or(0);
            assert!(pong >= 29, "pong bytes {pong}");
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(saw, "two nodes must see each other via addnode");
    na.shutdown().await;
    // nb moved? keep drop
    let _ = nb;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(_d0);
    let _ = std::fs::remove_dir_all(_d1);
}

#[test]
fn rpc_honesty_mempool_budget_and_network_identity() {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-rpc-honest-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    let q = Arc::new(Query::open_or_create(dir.join("store")).unwrap());
    let mp = MempoolHub::open_with_weight(dir.join("mempool"), Arc::clone(&q), 50_000_000).unwrap();
    let ctx = RpcContext {
        query: q,
        mempool: Some(mp),
        network: Network::Regtest,
        start: Instant::now(),
        stop: Arc::new(AtomicBool::new(false)),
        connections: Arc::new(AtomicU64::new(0)),
        initial_block_download: Arc::new(AtomicBool::new(false)),
        subversion: rbitcoin_primitives::rbitcoin_subversion(
            env!("CARGO_PKG_VERSION"),
            &[] as &[&str],
        )
        .unwrap(),
        regtest: None,
        peers: None,
        chain: None,
        addrman: None,
        peers_path: None,
        logpath: String::new(),
        active: std::sync::Arc::new(std::sync::Mutex::new(RpcActive::default())),
        permit_bare_multisig: true,
        alert_notify: None,
        alert_fired: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let mem = dispatch(&ctx, "getmempoolinfo", vec![]).unwrap();
    assert_eq!(
        mem["maxmempool"].as_u64(),
        Some(50_000_000),
        "maxmempool must be the hub weight budget, not a hardcoded 300M"
    );
    let net = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    assert_ne!(
        net["version"].as_u64(),
        Some(270000),
        "must not impersonate Bitcoin Core 27.0"
    );
    assert_eq!(
        net["version"].as_u64(),
        Some(rpc_client_version(env!("CARGO_PKG_VERSION"))),
    );
    assert_eq!(
        net["subversion"].as_str().unwrap(),
        rbitcoin_primitives::rbitcoin_subversion(env!("CARGO_PKG_VERSION"), &[] as &[&str],)
            .unwrap()
    );
    assert_eq!(
        rpc_client_version("0.1.0"),
        100,
        "0.1.0 is major*10000+minor*100+patch (not 10000, which is 1.0.0)"
    );
    assert_eq!(
        rpc_client_version("0.5.0"),
        500,
        "0.5.0 is the same mapping (not Core 27.0 / 270000)"
    );
    assert_eq!(
        rpc_client_version("0.5.1"),
        501,
        "0.5.1 patch is +1 on the Core-style integer"
    );
    let flags = rbitcoin_net::local_service_flags();
    let bits = flags.to_u64();
    let hex = format!("{bits:016x}");
    assert_eq!(net["localservices"].as_str(), Some(hex.as_str()));
    let names = net["localservicesnames"].as_array().unwrap();
    let names: Vec<&str> = names.iter().filter_map(|v| v.as_str()).collect();
    assert!(names.contains(&"NETWORK"));
    assert!(names.contains(&"WITNESS"));
    assert!(names.contains(&"P2P_V2"));
    assert!(
        !names.contains(&"NETWORK_LIMITED"),
        "we do not advertise NETWORK_LIMITED: {names:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rpc_active_leave_removes_by_id_not_last() {
    let mut active = RpcActive::default();
    let slow = active.enter("slow");
    let _fast = active.enter("fast");
    active.leave(slow);
    let names: Vec<String> = active.snapshot().into_iter().map(|(m, _)| m).collect();
    assert_eq!(names, vec!["fast".to_string()]);
}

#[test]
fn testmempoolaccept_rbf_does_not_evict_conflict() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
    use rbitcoin_primitives::Height;

    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }
    let (ctx, dir) = ctx_empty();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(
        &ctx.query,
        &params,
        Height::GENESIS,
        &genesis,
        Milestone::NONE,
    )
    .unwrap();
    let (_tip, _tip_time, coinbase_txids) = rbitcoin_consensus::pad_empty_from(
        &ctx.query,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        101,
        1,
    );
    let mp = ctx.mempool.as_ref().expect("mempool");
    mp.set_relay_enabled(true);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let low = Transaction {
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
    mp.accept_tx(&low).expect("low");
    let high = Transaction {
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
            value: Amount::from_sat(50_0000_0000 - 50_000),
            script_pubkey: spk,
        }],
    };
    let high_hex = hex_encode(serialize(&high));
    let row = dispatch(&ctx, "testmempoolaccept", vec![json!([high_hex])]).unwrap();
    assert_eq!(row[0]["allowed"], json!(true), "{row}");
    assert!(
        mp.contains(&low.compute_txid()),
        "testmempoolaccept must not RBF-evict the live conflict"
    );
    assert!(
        !mp.contains(&high.compute_txid()),
        "trial replacement must not remain in the mempool"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
