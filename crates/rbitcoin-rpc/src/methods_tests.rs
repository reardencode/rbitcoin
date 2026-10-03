use super::*;
use bitcoin::consensus::{deserialize, encode::serialize_hex};
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::{Address, Amount, Network as BtcNetwork, Transaction, Txid};
use rbitcoin_primitives::{Height, Network};
use rbitcoin_store::testutil::TempDir;
use std::str::FromStr;
use std::time::Duration;

fn ctx_empty() -> (RpcContext, TempDir) {
    let dir = TempDir::labeled("rpc-meth").expect("temp dir");
    let q = Arc::new(Query::open_or_create_tiny(dir.join("store")).unwrap());
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

        logpath: String::new(),
        active: std::sync::Arc::new(std::sync::Mutex::new(RpcActive::default())),

        alert_notify: None,
        alert_fired: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    (ctx, dir)
}

fn named(obj: Value) -> RpcParams {
    RpcParams::named(obj.as_object().cloned().expect("object"))
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
fn help_and_getrpcinfo_list_every_dispatched_method() {
    let (ctx, dir) = ctx_empty();
    let help = dispatch(&ctx, "help", vec![]).expect("help");
    let help_text = help.as_str().expect("help string");
    let info = dispatch(&ctx, "getrpcinfo", vec![]).expect("getrpcinfo");
    let listed = info["methods"]
        .as_array()
        .expect("methods array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();
    for name in [
        "generate",
        "mockscheduler",
        "addpeeraddress",
        "getnodeaddresses",
    ] {
        assert!(
            help_text.lines().any(|l| l == name),
            "help missing {name}: {help_text}"
        );
        assert!(
            listed.contains(&name),
            "getrpcinfo.methods missing {name}: {listed:?}"
        );
        let err = dispatch(&ctx, name, vec![]).err();
        if let Some(e) = err {
            assert_ne!(
                e["message"].as_str(),
                Some("Method not found"),
                "{name} dispatched as missing"
            );
        }
    }
    for name in listed {
        let err = dispatch(&ctx, name, vec![]).err();
        if let Some(e) = err {
            assert_ne!(
                e["message"].as_str(),
                Some("Method not found"),
                "{name} in METHOD_LIST but dispatch misses it"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getorphantxs_is_hidden_and_lists_parked() {
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    let (ctx, dir) = ctx_empty();
    let help_all = dispatch(&ctx, "help", vec![]).unwrap();
    let s = help_all.as_str().unwrap();
    assert!(
        !s.lines().any(|l| l == "getorphantxs"),
        "getorphantxs must stay hidden from help()"
    );
    let one = dispatch(&ctx, "help", vec![json!("getorphantxs")]).unwrap();
    let one_s = one.as_str().unwrap();
    assert!(one_s.contains("getorphantxs"));
    assert!(!one_s.contains("unknown command: getorphantxs"));

    let empty = dispatch(&ctx, "getorphantxs", vec![]).unwrap();
    assert_eq!(empty, json!([]));

    let bool_err = dispatch(&ctx, "getorphantxs", vec![json!(true)]).unwrap_err();
    assert_eq!(bool_err["code"], ERR_TYPE_ERROR);
    assert!(bool_err["message"]
        .as_str()
        .unwrap()
        .contains("Verbosity was boolean but only integer allowed"));
    let bad = dispatch(&ctx, "getorphantxs", vec![json!(-1)]).unwrap_err();
    assert_eq!(bad["code"], ERR_INVALID_PARAMETER);
    assert!(bad["message"]
        .as_str()
        .unwrap()
        .contains("Invalid verbosity value -1"));

    let mp = ctx.mempool.as_ref().unwrap();
    let tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([9u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let err = mp.accept_tx_from(&tx, Some(3)).unwrap_err();
    assert!(
        matches!(err, rbitcoin_net::AcceptError::Orphaned { .. }),
        "{err}"
    );
    let ids = dispatch(&ctx, "getorphantxs", vec![]).unwrap();
    let txid = hash_hex_display(&tx.compute_txid().to_byte_array());
    assert_eq!(ids, json!([txid]));
    let v1 = dispatch(&ctx, "getorphantxs", vec![json!(1)]).unwrap();
    assert_eq!(v1[0]["txid"], json!(txid));
    assert_eq!(v1[0]["from"], json!([3]));
    assert!(v1[0].get("hex").is_none());
    let v2 = dispatch(&ctx, "getorphantxs", vec![json!(2)]).unwrap();
    assert!(v2[0]["hex"].as_str().unwrap().len() > 20);
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
    assert_eq!(mem["orphanage"]["size"], 0);
    assert_eq!(mem["orphanage"]["bytes"], 0);
    let raw = dispatch(&ctx, "getrawmempool", vec![]).unwrap();
    assert_eq!(raw, json!([]));
    let seq = dispatch(&ctx, "getrawmempool", vec![json!(false), json!(true)]).unwrap();
    assert_eq!(seq["txids"], json!([]));
    assert_eq!(seq["mempool_sequence"].as_u64().unwrap(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getnetworkhashps_help_names_chainwork() {
    let h = super::method_help("getnetworkhashps");
    assert!(
        h.to_lowercase().contains("chainwork") && !h.contains("Dummy 2-work"),
        "hashrate help must name chainwork, not dummy 2-work: {h}"
    );
}

fn chainwork_f64(hex: &str) -> f64 {
    let b = rbitcoin_primitives::hex_decode(hex).unwrap();
    b.iter().fold(0.0, |a, x| a * 256.0 + f64::from(*x))
}

#[test]
fn method_help_named_arms_and_unknown() {
    for m in [
        "estimatesmartfee",
        "estimaterawfee",
        "getblockchaininfo",
        "getblockstats",
        "generatetoaddress",
        "generateblock",
        "generate",
        "mockscheduler",
        "generatetodescriptor",
        "scantxoutset",
        "decoderawtransaction",
        "decodescript",
        "validateaddress",
        "gettxout",
        "sendrawtransaction",
        "getchaintips",
        "getdeploymentinfo",
        "getblocktemplate",
        "getmininginfo",
        "getnetworkhashps",
        "prioritisetransaction",
        "getprioritisedtransactions",
        "submitblock",
        "submitheader",
        "getpeerinfo",
        "getorphantxs",
        "help",
        "echo",
        "ping",
        "getblock",
        "getrawmempool",
        "setmocktime",
        "preciousblock",
    ] {
        let h = super::method_help(m);
        assert!(
            h.starts_with(m),
            "help for listed method {m} must start with the name: {h}"
        );
        assert!(
            !h.starts_with("unknown method"),
            "listed method {m} must not be unknown: {h}"
        );
    }
    assert_eq!(
        super::method_help("not-a-method"),
        "unknown method not-a-method"
    );
}

#[test]
fn getmempoolinfo_permitbaremultisig_is_always_true() {
    let (ctx, dir) = ctx_empty();
    let mem = dispatch(&ctx, "getmempoolinfo", vec![]).unwrap();
    assert_eq!(
        mem["permitbaremultisig"], true,
        "Libre has no Core IsStandard bare-multisig gate"
    );
    assert_eq!(mem["fullrbf"], true);
    assert!(mem["maxdatacarriersize"].is_null());
    assert_eq!(mem["limitclustercount"], 64);
    assert_eq!(mem["limitclustersize"], 101_000);
    assert_eq!(
        serde_json::to_string(&mem["mempoolminfee"]).unwrap(),
        "0.00000100"
    );
    assert_eq!(
        serde_json::to_string(&mem["minrelaytxfee"]).unwrap(),
        "0.00000100"
    );
    assert_eq!(
        serde_json::to_string(&mem["total_fee"]).unwrap(),
        "0.00000000"
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

/// CLN stock `bcli` parses these Core JSON shapes (docs/lightning.md).
#[test]
fn cln_bcli_rpc_shapes() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let info = dispatch(&ctx, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(info["chain"], "regtest", "{info}");
    assert!(info["blocks"].as_u64().is_some(), "{info}");
    assert!(info["headers"].as_u64().is_some(), "{info}");
    assert!(info["initialblockdownload"].as_bool().is_some(), "{info}");

    for target in [2_u64, 6, 12, 100] {
        let fee = dispatch(&ctx, "estimatesmartfee", vec![json!(target)]).unwrap();
        assert!(
            fee.get("feerate").is_some() || fee.get("errors").is_some(),
            "estimatesmartfee {target}: {fee}"
        );
        if let Some(n) = fee["blocks"].as_u64() {
            assert!(n >= 1, "{fee}");
        }
    }

    let (addr, _) = p2wpkh_regtest();
    dispatch(&ctx, "generatetoaddress", vec![json!(1), json!(addr)]).unwrap();
    let tip = dispatch(&ctx, "getbestblockhash", vec![])
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let raw = dispatch(&ctx, "getblock", vec![json!(tip), json!(0)]).unwrap();
    let hex = raw.as_str().expect("verbosity 0 hex");
    assert!(hex.len() > 160 && hex.len() % 2 == 0, "{hex}");

    let missing = dispatch(&ctx, "gettxout", vec![json!("00".repeat(32)), json!(0)]).unwrap();
    assert!(
        missing.is_null(),
        "unknown outpoint must be JSON null: {missing}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Core's result without an estimate: `errors` and `blocks`, and no `feerate`.
/// The success object and the `mempoolminfee` floor are pinned on
/// `smart_fee_json`.
#[test]
fn estimatesmartfee_core_result_shape() {
    let (ctx, dir) = ctx_empty();
    let r = dispatch(&ctx, "estimatesmartfee", vec![json!(2)]).unwrap();
    assert!(
        r.get("feerate").is_none(),
        "no estimate has no feerate: {r}"
    );
    assert_eq!(
        r["errors"][0], "Insufficient data or no feerate found",
        "{r}"
    );
    assert_eq!(r["blocks"], 2, "{r}");
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
    let raw = dispatch(&ctx, "estimaterawfee", vec![json!(1)]).unwrap();
    assert!(raw.get("feerate").is_some(), "{raw}");
    assert!(raw.get("short").is_none(), "{raw}");
    let _ = dispatch(&ctx, "estimaterawfee", vec![json!(1), json!(1)]).unwrap();
    let _ = dispatch(&ctx, "estimatesmartfee", vec![json!(1), json!("unset")]).unwrap();
    let _ = dispatch(
        &ctx,
        "estimatesmartfee",
        vec![json!(1), json!("conservative")],
    )
    .unwrap();
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
        "decode of 00 is not serving-only refuse, got {e}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn blocksonly_sendraw_admits_valid_tx() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    ctx.mempool.as_ref().unwrap().set_relay_enabled(false);
    let (hex, spend) = mature_coinbase_spend_hex(&ctx, 50_0000_0000 - 1_000);
    let off = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    assert_eq!(off["localrelay"], false, "{off}");
    let ok = dispatch(&ctx, "sendrawtransaction", vec![json!(hex)]).unwrap();
    assert_eq!(
        ok.as_str().unwrap(),
        &spend.compute_txid().to_string(),
        "{ok}"
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
    let e2 = dispatch(&ctx, "combinerawtransaction", vec![]).unwrap_err();
    assert_eq!(e2["code"], ERR_METHOD_NOT_FOUND);
    let utxo = dispatch(&ctx, "gettxoutsetinfo", vec![]).unwrap_err();
    assert_eq!(utxo["code"], ERR_METHOD_NOT_FOUND);
    assert!(
        utxo["message"]
            .as_str()
            .unwrap_or("")
            .contains("not supported"),
        "{utxo}"
    );
    let e3 = dispatch(&ctx, "syncwithvalidationinterfacequeue", vec![]).unwrap_err();
    assert_eq!(e3["code"], ERR_METHOD_NOT_FOUND);
    assert_eq!(e3["message"], "Method not found");
    let help = dispatch(&ctx, "help", vec![]).unwrap();
    assert!(!help
        .as_str()
        .unwrap()
        .lines()
        .any(|l| { l == "syncwithvalidationinterfacequeue" || l == "gettxoutsetinfo" }));
    let info = dispatch(&ctx, "getrpcinfo", vec![]).unwrap();
    let listed: Vec<&str> = info["methods"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(!listed.contains(&"syncwithvalidationinterfacequeue"));
    assert!(!listed.contains(&"gettxoutsetinfo"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dispatch_getblockcount_empty_store() {
    let (ctx, dir) = ctx_empty();
    let resp = dispatch(&ctx, "getblockcount", vec![]).unwrap();
    assert_eq!(resp, json!(0));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn named_params_getblock_object() {
    let (ctx, dir) = ctx_empty();
    // Empty object is valid for methods with no args.
    let resp = dispatch(&ctx, "getblockcount", RpcParams::named(Default::default())).unwrap();
    assert_eq!(resp, json!(0));

    let h = dispatch(&ctx, "help", named(json!({"command": "getblockchaininfo"}))).unwrap();
    let s = h.as_str().unwrap();
    assert!(s.starts_with("getblockchaininfo\n"), "{s}");

    let unknown =
        dispatch(&ctx, "help", named(json!({"random": "getblockchaininfo"}))).unwrap_err();
    assert_eq!(unknown["code"], ERR_INVALID_PARAMETER);
    assert!(
        unknown["message"]
            .as_str()
            .unwrap()
            .contains("Unknown named parameter"),
        "{unknown}"
    );

    // Named height on empty store: accepted as params (not "named not supported").
    let gh = dispatch(&ctx, "getblockhash", named(json!({"height": 0}))).unwrap_err();
    assert_ne!(
        gh["message"].as_str().unwrap_or(""),
        "named params not supported; use array"
    );
    assert_eq!(gh["code"], ERR_INVALID_PARAMETER); // height out of range

    let missing = dispatch(&ctx, "getblock", RpcParams::named(Default::default())).unwrap_err();
    assert_eq!(missing["code"], ERR_INVALID_PARAMS);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn echo_positional_named_and_mixed_args() {
    let (ctx, dir) = ctx_empty();

    let empty = dispatch(&ctx, "echo", vec![]).unwrap();
    assert_eq!(empty, json!([]));

    let named_echo = dispatch(&ctx, "echo", named(json!({"arg0": 0, "arg9": 9}))).unwrap();
    let mut want = vec![Value::Null; 10];
    want[0] = json!(0);
    want[9] = json!(9);
    assert_eq!(named_echo, Value::Array(want));

    let arg1 = dispatch(&ctx, "echo", named(json!({"arg1": 1}))).unwrap();
    assert_eq!(arg1, json!([Value::Null, 1]));

    let arg9_null = dispatch(&ctx, "echo", named(json!({"arg9": null}))).unwrap();
    assert_eq!(arg9_null, json!(vec![Value::Null; 10]));

    // AuthServiceProxy mixed: echo(0, 1, arg3=3, arg5=5)
    let mixed = dispatch(
        &ctx,
        "echo",
        named(json!({"args": [0, 1], "arg3": 3, "arg5": 5})),
    )
    .unwrap();
    assert_eq!(mixed, json!([0, 1, Value::Null, 3, Value::Null, 5]));

    let twice = dispatch(&ctx, "echo", named(json!({"args": [0, 1], "arg1": 1}))).unwrap_err();
    assert_eq!(twice["code"], ERR_INVALID_PARAMETER);
    assert!(
        twice["message"]
            .as_str()
            .unwrap()
            .contains("specified twice"),
        "{twice}"
    );

    let twice_null = dispatch(
        &ctx,
        "echo",
        named(json!({"args": [0, null, 2], "arg1": 1})),
    )
    .unwrap_err();
    assert_eq!(twice_null["code"], ERR_INVALID_PARAMETER);

    // Mixed positional `args` is echo-only; other methods reject the named key.
    let gh = dispatch(&ctx, "getblockhash", named(json!({"args": [0]}))).unwrap_err();
    assert_eq!(gh["code"], ERR_INVALID_PARAMETER);
    assert_eq!(gh["message"], "Unknown named parameter args");

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
    ] {
        let _ = dispatch(&ctx, m, &params);
    }
    let decoded = dispatch(&ctx, "decodescript", vec![json!("51")]).unwrap();
    assert_eq!(decoded["type"], json!("nonstandard"));
    // estimatesmartfee requires conf_target (rpc_estimatefee.py)
    let _ = dispatch(&ctx, "estimatesmartfee", vec![]).unwrap_err();
    let _ = dispatch(&ctx, "estimatesmartfee", vec![json!(6)]).unwrap();
    let _ = dispatch(&ctx, "getblockcount", RpcParams::named(Default::default())).unwrap();
    let _ = dispatch(&ctx, "nosuch", vec![]).unwrap_err();
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

        logpath: String::new(),
        active: std::sync::Arc::new(std::sync::Mutex::new(RpcActive::default())),

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

/// Single-txid mempool RPC must not scan/clone the live set.
#[test]
fn mempool_txid_lookups_do_not_list_live() {
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
    use rbitcoin_primitives::Height;

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
    assert!(mp.is_local_origin(&local.compute_txid()));
    assert!(!mp.is_local_origin(&parent.compute_txid()));

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

#[test]
fn getmempoolentry_vsize_ceils_weight() {
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_consensus::policy::get_virtual_size;
    use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
    use rbitcoin_primitives::Height;

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
        1,
    );
    let mp = ctx.mempool.as_ref().expect("mempool");
    mp.set_relay_enabled(true);
    let wit_script = ScriptBuf::from_bytes(vec![0x51]);
    let p2wsh = ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::hash(wit_script.as_bytes()));
    let fund = Transaction {
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
            script_pubkey: p2wsh,
        }],
    };
    mp.accept_tx(&fund).expect("fund");
    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: fund.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::from_slice(&[wit_script.to_bytes()]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 2_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    mp.accept_tx(&spend).expect("p2wsh spend");
    let weight = spend.weight().to_wu();
    assert_ne!(
        weight % 4,
        0,
        "witness remainder distinguishes floor vs ceil"
    );
    let want = get_virtual_size(weight);
    let fund_v = get_virtual_size(fund.weight().to_wu());
    let hex = hash_hex_display(&spend.compute_txid().to_byte_array());
    let entry = dispatch(&ctx, "getmempoolentry", vec![json!(hex.clone())]).unwrap();
    assert_eq!(entry["vsize"], want);
    assert_eq!(entry["ancestorsize"], fund_v + want);
    assert_eq!(entry["descendantsize"], want);
    assert_ne!(entry["vsize"], weight / 4);
    let verbose = dispatch(&ctx, "getrawmempool", vec![json!(true)]).unwrap();
    assert_eq!(verbose[&hex]["vsize"], want);
    assert_eq!(
        entry, verbose[&hex],
        "getmempoolentry must match verbose getrawmempool (including wtxid)"
    );
    let ids = dispatch(&ctx, "getrawmempool", vec![]).unwrap();
    let arr = ids.as_array().expect("txid array");
    let mut sorted = arr.clone();
    sorted.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    assert_eq!(
        arr, &sorted,
        "non-verbose getrawmempool is display-hex sorted"
    );
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
        crate::submit_received_block(&self.0, block)
    }

    fn set_mock_time(&self, timestamp: i64) -> Result<(), String> {
        self.0.clock.set_mock(timestamp);
        Ok(())
    }
}

fn ctx_regtest_hub() -> (RpcContext, TempDir, Arc<rbitcoin_net::ChainHub>) {
    ctx_regtest_hub_with_weight(300_000_000)
}

fn ctx_regtest_hub_with_weight(max_wu: u64) -> (RpcContext, TempDir, Arc<rbitcoin_net::ChainHub>) {
    use rbitcoin_consensus::{ChainParams, Milestone};
    let dir = TempDir::labeled("rpc-gen").expect("temp dir");
    let hub = Arc::new(rbitcoin_net::ChainHub::new(
        Query::open_or_create_tiny(dir.join("store")).unwrap(),
        ChainParams::regtest(),
        Milestone::NONE,
    ));
    hub.ensure_genesis().unwrap();
    let mp = MempoolHub::open_with_weight(dir.join("mempool"), hub.query.clone(), max_wu).unwrap();
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

        logpath: String::new(),
        active: std::sync::Arc::new(std::sync::Mutex::new(RpcActive::default())),

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

fn assert_getblock_core_header_keys(obj: &Value, header: &Value) {
    assert!(obj["difficulty"].as_f64().is_some(), "difficulty: {obj}");
    assert_eq!(obj["difficulty"], header["difficulty"]);
    let vh = obj["versionHex"].as_str().expect("versionHex");
    assert_eq!(vh.len(), 8);
    assert_eq!(vh, header["versionHex"].as_str().unwrap());
    let cw = obj["chainwork"].as_str().expect("chainwork");
    assert_eq!(cw.len(), 64);
    assert_eq!(cw, header["chainwork"].as_str().unwrap());
}

#[test]
fn getblock_verbosity_2_size_weight_and_tx_fee() {
    use bitcoin::consensus::encode::deserialize;

    let (ctx, dir, _hub) = ctx_regtest_hub();
    let (hex, _spend) = mature_coinbase_spend_hex(&ctx, 50_0000_0000 - 1_000);
    dispatch(&ctx, "sendrawtransaction", vec![json!(hex)]).unwrap();
    let hashes = dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let tip = hashes.as_array().unwrap()[0].clone();
    let v2 = dispatch(&ctx, "getblock", vec![tip.clone(), json!(2)]).unwrap();
    let coinbase = &v2["tx"][0];
    assert!(
        coinbase["vin"][0].get("coinbase").is_some(),
        "coinbase vin must use Bitcoin Core's coinbase field: {coinbase}"
    );
    assert!(
        coinbase["vin"][0].get("txid").is_none(),
        "coinbase vin must not expose a normal prevout: {coinbase}"
    );
    let confirmed = dispatch(
        &ctx,
        "getrawtransaction",
        vec![coinbase["txid"].clone(), json!(true)],
    )
    .unwrap();
    assert_eq!(confirmed["confirmations"], json!(1));
    assert_eq!(confirmed["blockhash"], tip);
    assert_eq!(confirmed["blocktime"], confirmed["time"]);
    let raw = dispatch(&ctx, "getblock", vec![tip.clone(), json!(0)]).unwrap();
    let raw_bytes = rbitcoin_primitives::hex_decode(raw.as_str().unwrap()).unwrap();
    let block: bitcoin::Block = deserialize(&raw_bytes).unwrap();
    assert_eq!(v2["size"].as_u64().unwrap(), block.total_size() as u64);
    assert_eq!(v2["weight"].as_u64().unwrap(), block.weight().to_wu());
    assert_eq!(
        v2["strippedsize"].as_u64().unwrap(),
        (block.weight().to_wu() - block.total_size() as u64) / 3
    );
    // Core verbosity 1 carries the same three; mempool's block indexer
    // stores `size` NOT NULL and fails every block without it.
    let v1 = dispatch(&ctx, "getblock", vec![tip, json!(1)]).unwrap();
    for field in ["size", "strippedsize", "weight"] {
        assert!(v1[field].is_u64(), "v1 {field} missing: {v1}");
        assert_eq!(v1[field], v2[field], "v1 vs v2 {field}");
    }
    let txs = v2["tx"].as_array().unwrap();
    assert!(txs[0].get("fee").is_none(), "coinbase must omit fee: {v2}");
    let fee = txs[1]["fee"].as_f64().expect("spend fee");
    assert!((fee - (1_000.0 / 1e8)).abs() < 1e-10, "fee={fee} v2={v2}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getblock_named_verbose_genesis_and_hex() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let genesis = dispatch(&ctx, "getblockhash", vec![json!(0)]).unwrap();
    let named = named(json!({"blockhash": genesis.clone(), "verbose": true}));
    let v = dispatch(&ctx, "getblock", named).unwrap();
    assert!(
        v.get("previousblockhash").is_none(),
        "genesis omits previousblockhash: {v}"
    );
    assert_eq!(v["tx"].as_array().unwrap().len(), 1);
    let hex = dispatch(&ctx, "getblock", vec![genesis.clone(), json!(0)]).unwrap();
    assert!(hex.as_str().unwrap().len() > 160);
    let genesis_hdr = dispatch(&ctx, "getblockheader", vec![genesis.clone()]).unwrap();
    assert!(
        genesis_hdr.get("previousblockhash").is_none(),
        "{genesis_hdr}"
    );
    assert_eq!(genesis_hdr["target"].as_str().unwrap().len(), 64);
    let info = dispatch(&ctx, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(info["bits"], genesis_hdr["bits"]);
    assert_eq!(info["target"], genesis_hdr["target"]);
    let diff = serde_json::to_string(&dispatch(&ctx, "getdifficulty", vec![]).unwrap()).unwrap();
    assert!(!diff.contains('e') && !diff.contains('E'), "{diff}");
    dispatch(
        &ctx,
        "generatetoaddress",
        vec![json!(1), json!(p2wpkh_regtest().0)],
    )
    .unwrap();
    let parent = dispatch(&ctx, "getblockheader", vec![genesis]).unwrap();
    assert!(parent["nextblockhash"].as_str().is_some(), "{parent}");
    let tip = dispatch(&ctx, "getbestblockhash", vec![]).unwrap();
    let tip_hdr = dispatch(&ctx, "getblockheader", vec![tip.clone()]).unwrap();
    assert!(tip_hdr.get("nextblockhash").is_none(), "{tip_hdr}");
    let parent_hash = tip_hdr["previousblockhash"].clone();
    dispatch(&ctx, "invalidateblock", vec![tip.clone()]).unwrap();
    let gone = dispatch(&ctx, "getblockheader", vec![tip.clone()]).unwrap();
    assert_eq!(gone["confirmations"], json!(-1), "{gone}");
    assert_eq!(gone["previousblockhash"], parent_hash);
    let body = dispatch(&ctx, "getblock", vec![tip, json!(1)]).unwrap();
    assert_eq!(body["confirmations"], json!(-1), "{body}");
    assert!(!body["tx"].as_array().unwrap().is_empty(), "{body}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Core `mediantime` on an inactive header is the median of that header and
/// up to 10 ancestors, not the header's own timestamp.
#[test]
fn inactive_header_mediantime_is_branch_median() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let addr = p2wpkh_regtest().0;
    let mut hashes = Vec::new();
    for i in 0..12u32 {
        let t = 1_700_000_000u64 + u64::from(i) * 1_000;
        dispatch(&ctx, "setmocktime", vec![json!(t)]).unwrap();
        let mined = dispatch(&ctx, "generatetoaddress", vec![json!(1), json!(addr)]).unwrap();
        hashes.push(mined.as_array().unwrap()[0].clone());
    }
    let old_tip = hashes[11].clone();
    dispatch(&ctx, "invalidateblock", vec![hashes[9].clone()]).unwrap();
    let gone = dispatch(&ctx, "getblockheader", vec![old_tip.clone()]).unwrap();
    assert_eq!(gone["confirmations"], json!(-1), "{gone}");
    assert_eq!(gone["height"], json!(12), "{gone}");
    assert_eq!(gone["previousblockhash"], hashes[10], "{gone}");
    // Heights 2..=12. Sorted median is height 7: 1_700_000_000 + 6*1000.
    assert_eq!(gone["mediantime"], json!(1_700_006_000u64), "{gone}");
    let body = dispatch(&ctx, "getblock", vec![old_tip, json!(1)]).unwrap();
    assert_eq!(body["confirmations"], json!(-1), "{body}");
    assert_eq!(body["mediantime"], gone["mediantime"], "{body}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn miniwallet_raw_scan_and_gettxout() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let desc = "raw(51)";
    let hashes = dispatch(&ctx, "generatetodescriptor", vec![json!(2), json!(desc)]).unwrap();
    assert_eq!(hashes.as_array().unwrap().len(), 2);
    assert_eq!(dispatch(&ctx, "getblockcount", vec![]).unwrap(), json!(2));

    ctx.query.store().reset_tx_full_gets();
    let scan = dispatch(&ctx, "scantxoutset", vec![json!("start"), json!([desc])]).unwrap();
    assert!(
        ctx.query.store().tx_full_gets().is_empty(),
        "scantxoutset shindex must not zip seqsigwit: {:?}",
        ctx.query.store().tx_full_gets()
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

    assert_eq!(
        dispatch(&ctx, "scantxoutset", vec![json!("status")]).unwrap(),
        Value::Null
    );
    assert_eq!(
        dispatch(&ctx, "scantxoutset", vec![json!("abort")]).unwrap(),
        json!(false)
    );
    let empty = dispatch(&ctx, "scantxoutset", vec![json!("start"), json!([])]).unwrap();
    assert_eq!(empty["success"], true);
    assert_eq!(empty["txouts"], json!(-1));
    assert_eq!(empty["unspents"].as_array().unwrap().len(), 0, "{empty}");
    let unknown = dispatch(&ctx, "scantxoutset", vec![json!("nope")]).unwrap_err();
    assert_eq!(unknown["code"], ERR_INVALID_PARAMETER);
    assert!(
        unknown["message"]
            .as_str()
            .unwrap_or("")
            .contains("Invalid action"),
        "{unknown}"
    );

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
fn gettxout_disconnected_archive_row_is_null() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let (addr, _) = p2wpkh_regtest();
    dispatch(&ctx, "generatetoaddress", vec![json!(2), json!(addr)]).unwrap();
    let tip = dispatch(&ctx, "getbestblockhash", vec![])
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let blk = dispatch(&ctx, "getblock", vec![json!(tip.clone()), json!(2)]).unwrap();
    let cb_txid = blk["tx"][0]["txid"].as_str().unwrap().to_string();
    let live = dispatch(
        &ctx,
        "gettxout",
        vec![json!(cb_txid.clone()), json!(0), json!(false)],
    )
    .unwrap();
    assert_eq!(live["coinbase"], true, "{live}");
    dispatch(&ctx, "invalidateblock", vec![json!(tip)]).unwrap();
    let gone = dispatch(
        &ctx,
        "gettxout",
        vec![json!(cb_txid), json!(0), json!(false)],
    )
    .unwrap();
    assert!(
        gone.is_null(),
        "disconnected Class A row must not be a UTXO: {gone}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Core never adds the genesis coinbase output to the UTXO set.
#[test]
fn genesis_coinbase_is_not_a_utxo() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let genesis = bitcoin::blockdata::constants::genesis_block(BtcNetwork::Regtest);
    let spk = hex_encode(genesis.txdata[0].output[0].script_pubkey.as_bytes());
    let desc = format!("raw({spk})");
    dispatch(&ctx, "generatetodescriptor", vec![json!(1), json!(desc)]).unwrap();

    let g_hash = dispatch(&ctx, "getblockhash", vec![json!(0)]).unwrap();
    let g_blk = dispatch(&ctx, "getblock", vec![g_hash, json!(2)]).unwrap();
    let g_txid = g_blk["tx"][0]["txid"].as_str().unwrap().to_string();
    assert_eq!(g_txid, genesis.txdata[0].compute_txid().to_string());
    for include_mempool in [true, false] {
        let out = dispatch(
            &ctx,
            "gettxout",
            vec![json!(g_txid), json!(0), json!(include_mempool)],
        )
        .unwrap();
        assert!(out.is_null(), "include_mempool={include_mempool}: {out}");
    }
    let rest = dispatch_rest(&ctx, &format!("/rest/getutxos/{g_txid}-0.json"), "", &[]);
    assert_eq!(rest.status, axum::http::StatusCode::OK);
    let body: Value = serde_json::from_slice(&rest.body).unwrap();
    assert_eq!(body["bitmap"], "0", "{body}");

    let scan = dispatch(&ctx, "scantxoutset", vec![json!("start"), json!([desc])]).unwrap();
    let uns = scan["unspents"].as_array().unwrap();
    assert_eq!(uns.len(), 1, "only the height-1 coinbase: {scan}");
    assert_eq!(uns[0]["height"], 1, "{scan}");
    assert_ne!(uns[0]["txid"], json!(g_txid), "{scan}");
    assert_eq!(scan["total_amount"], uns[0]["amount"], "{scan}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Core refuses the genesis coinbase in `getrawtransaction`. Its txindex skips
/// height 0, so REST `/tx` answers 404.
#[test]
fn genesis_coinbase_is_not_an_ordinary_tx() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let genesis = bitcoin::blockdata::constants::genesis_block(BtcNetwork::Regtest);
    let g_txid = genesis.txdata[0].compute_txid().to_string();
    let g_hash = genesis.block_hash().to_string();
    for params in [
        vec![json!(g_txid)],
        vec![json!(g_txid), json!(1)],
        vec![json!(g_txid), json!(2), json!(g_hash)],
    ] {
        let e = dispatch(&ctx, "getrawtransaction", params.clone()).unwrap_err();
        assert_eq!(e["code"], ERR_INVALID_ADDRESS_OR_KEY, "{params:?}: {e}");
        assert_eq!(
            e["message"],
            "The genesis block coinbase is not considered an ordinary transaction and cannot be retrieved",
            "{params:?}: {e}"
        );
    }
    for ext in ["json", "hex", "bin"] {
        let rest = dispatch_rest(&ctx, &format!("/rest/tx/{g_txid}.{ext}"), "", &[]);
        assert_eq!(rest.status, axum::http::StatusCode::NOT_FOUND, "{ext}");
        let body = String::from_utf8(rest.body).unwrap();
        assert_eq!(body.trim_end(), format!("{g_txid} not found"), "{ext}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A Class A row that is no longer on the active chain still resolves
/// (TipThenAny), so verbose getrawtransaction and REST json must return the
/// tx object without block fields rather than an error.
#[test]
fn getrawtransaction_verbose_disconnected_tx_has_no_block_fields() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let (addr, _) = p2wpkh_regtest();
    dispatch(&ctx, "generatetoaddress", vec![json!(2), json!(addr)]).unwrap();
    let tip = dispatch(&ctx, "getbestblockhash", vec![])
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let blk = dispatch(&ctx, "getblock", vec![json!(tip.clone()), json!(2)]).unwrap();
    let cb_txid = blk["tx"][0]["txid"].as_str().unwrap().to_string();
    let connected = dispatch(
        &ctx,
        "getrawtransaction",
        vec![json!(cb_txid.clone()), json!(true)],
    )
    .unwrap();
    assert_eq!(connected["confirmations"], json!(1), "{connected}");
    assert_eq!(connected["blockhash"], json!(tip), "{connected}");

    dispatch(&ctx, "invalidateblock", vec![json!(tip)]).unwrap();
    let orphan = dispatch(
        &ctx,
        "getrawtransaction",
        vec![json!(cb_txid.clone()), json!(true)],
    )
    .unwrap_or_else(|e| panic!("verbose on a disconnected tx must not error: {e}"));
    assert_eq!(orphan["txid"], json!(cb_txid), "{orphan}");
    assert_eq!(orphan["in_mempool"], json!(false), "{orphan}");
    for field in ["confirmations", "blockhash", "blocktime", "time"] {
        assert!(orphan.get(field).is_none(), "{field}: {orphan}");
    }
    let hex = dispatch(
        &ctx,
        "getrawtransaction",
        vec![json!(cb_txid.clone()), json!(false)],
    )
    .unwrap();
    assert_eq!(orphan["hex"], hex, "{orphan}");

    let rest = dispatch_rest(&ctx, &format!("/rest/tx/{cb_txid}.json"), "", &[]);
    assert_eq!(
        rest.status,
        axum::http::StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&rest.body)
    );
    let body: serde_json::Value = serde_json::from_slice(&rest.body).unwrap();
    assert_eq!(body["txid"], json!(cb_txid), "{body}");
    assert!(body.get("confirmations").is_none(), "{body}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn decoderawtransaction_segwit_coinbase_keeps_txinwitness() {
    let (ctx, dir) = ctx_empty();
    let coinbase = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x51, 0x00]),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::from_slice(&[vec![0u8; 32]]),
        }],
        output: vec![bitcoin::TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::new_op_return([0xaa; 4]),
        }],
    };
    let obj = dispatch(
        &ctx,
        "decoderawtransaction",
        vec![json!(serialize_hex(&coinbase))],
    )
    .unwrap();
    let vin = &obj["vin"][0];
    assert_eq!(vin["coinbase"], json!("5100"), "{obj}");
    assert!(vin.get("txid").is_none(), "{obj}");
    assert_eq!(vin["txinwitness"], json!(["00".repeat(32)]), "{obj}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Disconnect clears confirmed[h] before popping the height fence. A verbose
/// lookup landing in that window must not error or invent a block.
#[test]
fn getrawtransaction_verbose_mid_disconnect_has_no_block_fields() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let (addr, _) = p2wpkh_regtest();
    dispatch(&ctx, "generatetoaddress", vec![json!(2), json!(addr)]).unwrap();
    let tip = dispatch(&ctx, "getbestblockhash", vec![])
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let blk = dispatch(&ctx, "getblock", vec![json!(tip.clone()), json!(2)]).unwrap();
    let cb_txid = blk["tx"][0]["txid"].as_str().unwrap().to_string();
    let height = Height(blk["height"].as_u64().unwrap() as u32);
    // Stop halfway through Query::disconnect_tip: confirmed cleared, fence not.
    ctx.query.store().confirmed.disconnect_tip(height).unwrap();
    let mid = dispatch(
        &ctx,
        "getrawtransaction",
        vec![json!(cb_txid.clone()), json!(true)],
    )
    .unwrap_or_else(|e| panic!("verbose mid-disconnect must not error: {e}"));
    assert_eq!(mid["txid"], json!(cb_txid), "{mid}");
    for field in ["confirmations", "blockhash", "blocktime", "time"] {
        assert!(mid.get(field).is_none(), "{field}: {mid}");
    }

    // A reorg can seat another block at that height before the fence pops.
    // That block does not hold the tx, so it must not be reported as its block.
    let (other_fk, other) = ctx
        .query
        .header_at_height(Height(height.0 - 1))
        .unwrap()
        .unwrap();
    ctx.query.store().confirmed.set(height, other_fk).unwrap();
    let replaced = dispatch(
        &ctx,
        "getrawtransaction",
        vec![json!(cb_txid.clone()), json!(true)],
    )
    .unwrap_or_else(|e| panic!("verbose after replacement must not error: {e}"));
    assert_ne!(
        replaced["blockhash"],
        json!(hash_hex_display(&other.hash)),
        "{replaced}"
    );
    for field in ["confirmations", "blockhash", "blocktime", "time"] {
        assert!(replaced.get(field).is_none(), "{field}: {replaced}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gettxout_leftover_is_connected_not_unconfirmed() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let (hex, spend) = mature_coinbase_spend_hex(&ctx, 50_0000_0000 - 1_000);
    dispatch(&ctx, "sendrawtransaction", vec![json!(hex)]).unwrap();
    let cb_txid = hash_hex_display(&spend.input[0].previous_output.txid.to_byte_array());
    let hidden = dispatch(&ctx, "gettxout", vec![json!(cb_txid.clone()), json!(0)]).unwrap();
    assert!(
        hidden.is_null(),
        "default include_mempool must hide mempool-spent confirmed out: {hidden}"
    );
    let shown = dispatch(
        &ctx,
        "gettxout",
        vec![json!(cb_txid), json!(0), json!(false)],
    )
    .unwrap();
    assert_eq!(shown["coinbase"], true, "{shown}");
    assert!(shown["confirmations"].as_u64().unwrap() >= 1, "{shown}");
    ctx.mempool.as_ref().unwrap().set_relay_enabled(false);
    dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let tid = spend.compute_txid();
    assert!(
        ctx.mempool.as_ref().unwrap().contains(&tid),
        "relay off must leave the confirmed tx in the hub"
    );
    let txid = hash_hex_display(&tid.to_byte_array());
    let utxo = dispatch(&ctx, "gettxout", vec![json!(txid), json!(0)]).unwrap();
    assert_ne!(
        utxo["confirmations"], 0,
        "default include_mempool must not treat a tip-connected leftover as mempool-only: {utxo}"
    );
    assert!(
        utxo["confirmations"].as_u64().unwrap() >= 1,
        "leftover must use the connected path: {utxo}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn mature_coinbase_spend(
    ctx: &RpcContext,
    keep_sat: u64,
    script: ScriptBuf,
) -> (String, Transaction) {
    dispatch(ctx, "generate", vec![json!(101)]).unwrap();
    spend_generated_coinbase(ctx, 1, keep_sat, script)
}

fn spend_generated_coinbase(
    ctx: &RpcContext,
    height: u32,
    keep_sat: u64,
    script: ScriptBuf,
) -> (String, Transaction) {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let hash = dispatch(ctx, "getblockhash", vec![json!(height)]).unwrap();
    let blk = dispatch(ctx, "getblock", vec![hash, json!(2)]).unwrap();
    let cb_txid = blk["tx"][0]["txid"].as_str().unwrap();
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
            value: Amount::from_sat(keep_sat),
            script_pubkey: script,
        }],
    };
    (hex_encode(serialize(&spend)), spend)
}

fn mature_coinbase_spend_hex(ctx: &RpcContext, keep_sat: u64) -> (String, Transaction) {
    mature_coinbase_spend(ctx, keep_sat, ScriptBuf::from_bytes(vec![0x51]))
}

fn generated_coinbase_value(ctx: &RpcContext, height: u32) -> u64 {
    let hash = dispatch(ctx, "getblockhash", vec![json!(height)]).unwrap();
    let blk = dispatch(ctx, "getblock", vec![hash, json!(2)]).unwrap();
    (blk["tx"][0]["vout"][0]["value"].as_f64().unwrap() * 100_000_000.0).round() as u64
}

fn default_max_raw_fee_sat(weight: u64) -> u64 {
    let vsize = rbitcoin_consensus::policy::get_virtual_size(weight);
    10_000u64.saturating_mul(vsize)
}

fn pin_sendraw_maxfeerate_at_default_and_one_sat_over(ctx: &RpcContext, at: u32, over: u32) {
    let cb = generated_coinbase_value(ctx, at);
    let probe = spend_generated_coinbase(ctx, at, cb - 1, ScriptBuf::from_bytes(vec![0x51])).1;
    let max_fee = default_max_raw_fee_sat(probe.weight().to_wu());
    assert!(max_fee > 0 && max_fee + 1 < cb, "max_fee={max_fee} cb={cb}");
    let (at_hex, _) =
        spend_generated_coinbase(ctx, at, cb - max_fee, ScriptBuf::from_bytes(vec![0x51]));
    let ok = dispatch(ctx, "sendrawtransaction", vec![json!(at_hex)]).unwrap();
    assert!(
        ok.as_str().is_some(),
        "exact default 10000 sat/vB must accept: {ok}"
    );
    let (over_hex, _) = spend_generated_coinbase(
        ctx,
        over,
        cb - max_fee - 1,
        ScriptBuf::from_bytes(vec![0x51]),
    );
    let e = dispatch(ctx, "sendrawtransaction", vec![json!(over_hex)]).unwrap_err();
    assert_eq!(e["code"], ERR_VERIFY_ERROR, "{e}");
    assert_eq!(
        e["message"], "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)",
        "{e}"
    );
}

fn pin_maxfeerate_json_shapes(ctx: &RpcContext) {
    for (v, code, msg) in [
        (json!(-1), ERR_INVALID_PARAMETER, "Amount out of range"),
        (json!("-2"), ERR_INVALID_PARAMETER, "Amount out of range"),
        (
            json!(1.5),
            ERR_INVALID_PARAMETER,
            "maxfeerate must be an integer sat/vB",
        ),
        (
            json!("nope"),
            ERR_INVALID_PARAMETER,
            "maxfeerate must be an integer sat/vB",
        ),
        (
            json!(true),
            ERR_TYPE_ERROR,
            "maxfeerate is not a number or string",
        ),
        (
            json!([]),
            ERR_TYPE_ERROR,
            "maxfeerate is not a number or string",
        ),
    ] {
        let e = dispatch(ctx, "sendrawtransaction", vec![json!("00"), v]).unwrap_err();
        assert_eq!(e["code"], code, "{e}");
        assert_eq!(e["message"], msg, "{e}");
    }
}

#[test]
fn sendrawtransaction_maxburnamount_default_rejects_op_return() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let burn = 1_000u64;
    let (hex, spend) = mature_coinbase_spend(&ctx, burn, ScriptBuf::from_bytes(vec![0x6a]));
    let e = dispatch(&ctx, "sendrawtransaction", vec![json!(hex.clone())]).unwrap_err();
    assert!(
        e["message"]
            .as_str()
            .unwrap_or("")
            .contains("maxburnamount"),
        "{e}"
    );
    let short = dispatch(
        &ctx,
        "sendrawtransaction",
        named(json!({
            "hexstring": hex,
            "maxfeerate": 0,
            "maxburnamount": "0.00000999"
        })),
    )
    .unwrap_err();
    assert!(
        short["message"]
            .as_str()
            .unwrap_or("")
            .contains("maxburnamount"),
        "amount−1 sat must reject: {short}"
    );
    pin_maxburn_json_shapes(&ctx, &hex);
    let pkg = dispatch(&ctx, "submitpackage", vec![json!([hex.clone()])]).unwrap_err();
    assert_eq!(pkg["code"], ERR_VERIFY_ERROR, "{pkg}");
    assert!(
        pkg["message"]
            .as_str()
            .unwrap_or("")
            .contains("maxburnamount"),
        "{pkg}"
    );
    ctx.mempool
        .as_ref()
        .unwrap()
        .accept_tx(&spend)
        .expect("P2P/admit path is not capped by RPC maxburnamount");
    let ok = dispatch(
        &ctx,
        "sendrawtransaction",
        named(json!({
            "hexstring": hex,
            "maxfeerate": 0,
            "maxburnamount": "0.00001000"
        })),
    )
    .unwrap();
    assert!(ok.as_str().is_some(), "{ok}");
    let _ = std::fs::remove_dir_all(&dir);
}

fn pin_maxburn_json_shapes(ctx: &RpcContext, hex: &str) {
    let n0 = dispatch(
        ctx,
        "sendrawtransaction",
        named(json!({
            "hexstring": hex,
            "maxfeerate": 0,
            "maxburnamount": 0
        })),
    )
    .unwrap_err();
    assert!(
        n0["message"]
            .as_str()
            .unwrap_or("")
            .contains("maxburnamount"),
        "numeric 0 BTC must still cap burn: {n0}"
    );
    let flt = dispatch(
        ctx,
        "sendrawtransaction",
        named(json!({
            "hexstring": hex,
            "maxfeerate": 0,
            "maxburnamount": 0.0
        })),
    )
    .unwrap_err();
    assert!(
        flt["message"]
            .as_str()
            .unwrap_or("")
            .contains("maxburnamount"),
        "float 0.0 BTC must still cap burn: {flt}"
    );
    let neg = dispatch(
        ctx,
        "sendrawtransaction",
        named(json!({
            "hexstring": hex,
            "maxfeerate": 0,
            "maxburnamount": -1
        })),
    )
    .unwrap_err();
    assert_eq!(neg["code"], ERR_INVALID_PARAMETER, "{neg}");
    assert_eq!(neg["message"], "Amount out of range", "{neg}");
    let typ = dispatch(
        ctx,
        "sendrawtransaction",
        named(json!({
            "hexstring": hex,
            "maxfeerate": 0,
            "maxburnamount": true
        })),
    )
    .unwrap_err();
    assert_eq!(typ["code"], ERR_TYPE_ERROR, "{typ}");
    assert_eq!(typ["message"], "Amount is not a number or string", "{typ}");
    for bad in [json!(""), json!("0.000000001"), json!("x.0")] {
        let e = dispatch(
            ctx,
            "sendrawtransaction",
            named(json!({
                "hexstring": hex,
                "maxfeerate": 0,
                "maxburnamount": bad
            })),
        )
        .unwrap_err();
        assert_eq!(e["code"], ERR_INVALID_PARAMETER, "{e}");
        assert_eq!(e["message"], "Invalid amount", "{e}");
    }
}

#[test]
fn submitpackage_child_fail_keeps_parent() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let (parent_hex, parent) = mature_coinbase_spend(
        &ctx,
        50_0000_0000 - 1_000,
        ScriptBuf::from_bytes(vec![0x51]),
    );
    let bad = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::from_slice(&[vec![0x01], vec![0x50, 0x01]]),
        }],
        output: vec![TxOut {
            value: parent.output[0].value + Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let bad_hex = hex_encode(serialize(&bad));
    let pkg = dispatch(
        &ctx,
        "submitpackage",
        vec![json!([parent_hex, bad_hex]), json!(0)],
    )
    .unwrap();
    assert_eq!(pkg["package_msg"], "transaction failed", "{pkg}");
    assert!(
        ctx.mempool
            .as_ref()
            .unwrap()
            .contains(&parent.compute_txid()),
        "Core submitpackage keeps a successful parent when a later member fails"
    );
    assert!(
        pkg["tx-results"][hash_hex_display(&bad.compute_wtxid().to_byte_array())]
            .get("error")
            .is_some(),
        "child must be the failed member, got {pkg}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rpc_submit_nonstandard_version_is_version() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let (parent_hex, parent) = mature_coinbase_spend(
        &ctx,
        50_0000_0000 - 1_000,
        ScriptBuf::from_bytes(vec![0x51]),
    );
    let child = Transaction {
        version: TxVersion::non_standard(0xffff_ffffu32 as i32),
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
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let child_hex = hex_encode(serialize(&child));
    let send = dispatch(&ctx, "sendrawtransaction", vec![json!(child_hex.clone())]).unwrap_err();
    assert_eq!(send["code"], ERR_VERIFY_REJECTED, "{send}");
    assert_eq!(send["message"], json!("version"), "{send}");
    let tma = dispatch(&ctx, "testmempoolaccept", vec![json!([child_hex.clone()])]).unwrap();
    assert_eq!(tma[0]["reject-reason"], json!("version"), "{tma}");
    let pkg = dispatch(
        &ctx,
        "submitpackage",
        vec![json!([parent_hex, child_hex]), json!(0)],
    )
    .unwrap();
    assert_eq!(pkg["package_msg"], "transaction failed", "{pkg}");
    let child_w = hash_hex_display(&child.compute_wtxid().to_byte_array());
    assert_eq!(
        pkg["tx-results"][&child_w]["error"],
        json!("version"),
        "{pkg}"
    );
    assert!(
        ctx.mempool
            .as_ref()
            .unwrap()
            .contains(&parent.compute_txid()),
        "parent must admit: {pkg}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
fn child_of(parent: &Transaction, fee_sat: u64) -> Transaction {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    Transaction {
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
            value: parent.output[0].value - Amount::from_sat(fee_sat),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

#[test]
fn mempool_under_pressure() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    let (ctx, dir, _hub) = ctx_regtest_hub();
    dispatch(&ctx, "generate", vec![json!(101)]).unwrap();
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let (parent_hex, parent) = spend_generated_coinbase(&ctx, 1, 50_0000_0000 - 1_000, spk.clone());
    let child = child_of(&parent, 1_000);
    let child_hex = hex_encode(serialize(&child));

    let unsorted = dispatch(
        &ctx,
        "testmempoolaccept",
        vec![json!([child_hex.clone(), parent_hex.clone()])],
    )
    .unwrap();
    assert_eq!(unsorted.as_array().map(|a| a.len()), Some(2), "{unsorted}");
    assert_eq!(
        unsorted[0]["package-error"],
        json!("package-not-sorted"),
        "{unsorted}"
    );
    assert_eq!(
        unsorted[1]["package-error"],
        json!("package-not-sorted"),
        "{unsorted}"
    );

    let garbage = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0u8; 32]),
                vout: 5,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: spk.clone(),
        }],
    };
    let missing = dispatch(
        &ctx,
        "testmempoolaccept",
        vec![json!([parent_hex.clone(), hex_encode(serialize(&garbage))])],
    )
    .unwrap();
    assert_eq!(missing.as_array().map(|a| a.len()), Some(2), "{missing}");
    assert_eq!(
        missing[0]["txid"],
        json!(hash_hex_display(&parent.compute_txid().to_byte_array())),
        "{missing}"
    );
    assert_eq!(missing[0]["allowed"], json!(true), "{missing}");
    assert_eq!(missing[1]["allowed"], json!(false), "{missing}");
    assert_eq!(
        missing[1]["reject-reason"],
        json!("missing-inputs"),
        "{missing}"
    );
    assert_eq!(ctx.mempool.as_ref().unwrap().live_count(), 0);

    let conflict_b = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: parent.input[0].previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 2_000),
            script_pubkey: spk.clone(),
        }],
    };
    let conflict_hex = hex_encode(serialize(&conflict_b));
    let tma = dispatch(
        &ctx,
        "testmempoolaccept",
        vec![json!([parent_hex.clone(), conflict_hex.clone()])],
    )
    .unwrap();
    assert_eq!(
        tma[0]["package-error"],
        json!("conflict-in-package"),
        "{tma}"
    );
    assert_eq!(
        tma[1]["package-error"],
        json!("conflict-in-package"),
        "{tma}"
    );
    let sub = dispatch(
        &ctx,
        "submitpackage",
        vec![json!([parent_hex, conflict_hex])],
    )
    .unwrap();
    assert_eq!(sub["package_msg"], json!("conflict-in-package"), "{sub}");
    for v in sub["tx-results"].as_object().unwrap().values() {
        assert_eq!(v["error"], json!("package-not-validated"), "{sub}");
    }

    pressure_tiny_weight();
    pressure_admit_then_cluster(&ctx, &spk);
    let _ = std::fs::remove_dir_all(&dir);
}

fn pressure_tiny_weight() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let (fee_ctx, fee_dir, _fee_hub) = ctx_regtest_hub_with_weight(1_000);
    let info = dispatch(&fee_ctx, "getmempoolinfo", vec![]).unwrap();
    let minrelay = info["minrelaytxfee"].as_f64().unwrap();
    let minfee = info["mempoolminfee"].as_f64().unwrap();
    assert!(
        minfee > minrelay,
        "tiny weight cap must raise mempoolminfee: {info}"
    );
    dispatch(&fee_ctx, "generate", vec![json!(101)]).unwrap();
    let cb = generated_coinbase_value(&fee_ctx, 1);
    let probe = spend_generated_coinbase(&fee_ctx, 1, cb - 1, spk.clone()).1;
    let vsize = rbitcoin_consensus::policy::get_virtual_size(probe.weight().to_wu());
    let minrelay_fee = vsize.div_ceil(10);
    let (low_hex, low) = spend_generated_coinbase(&fee_ctx, 1, cb - minrelay_fee, spk.clone());
    let low_child = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: low.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: spk,
        }],
    };
    let pkg = dispatch(
        &fee_ctx,
        "submitpackage",
        vec![json!([low_hex, hex_encode(serialize(&low_child))])],
    )
    .unwrap();
    assert_eq!(pkg["package_msg"], "transaction failed", "{pkg}");
    let parent_w = hash_hex_display(&low.compute_wtxid().to_byte_array());
    let child_w = hash_hex_display(&low_child.compute_wtxid().to_byte_array());
    let parent_err = pkg["tx-results"][&parent_w]["error"].as_str().unwrap_or("");
    assert!(
        parent_err.contains("mempool min fee not met"),
        "parent must stay individual min-fee fail, got {pkg}"
    );
    assert_eq!(
        pkg["tx-results"][&child_w]["error"],
        json!("bad-txns-inputs-missingorspent"),
        "{pkg}"
    );
    assert!(!fee_ctx
        .mempool
        .as_ref()
        .unwrap()
        .contains(&low.compute_txid()));
    assert!(!fee_ctx
        .mempool
        .as_ref()
        .unwrap()
        .contains(&low_child.compute_txid()));
    let _ = std::fs::remove_dir_all(&fee_dir);
}

fn pressure_admit_then_cluster(ctx: &RpcContext, spk: &ScriptBuf) {
    use bitcoin::consensus::encode::serialize;
    let (chain_hex, chain_parent) =
        spend_generated_coinbase(ctx, 2, 50_0000_0000 - 1_000, spk.clone());
    let chain_child = child_of(&chain_parent, 1_000);
    let chain_grand = child_of(&chain_child, 1_000);
    let chain_child_hex = hex_encode(serialize(&chain_child));
    let chain = dispatch(
        ctx,
        "submitpackage",
        vec![json!([
            chain_hex.clone(),
            chain_child_hex.clone(),
            hex_encode(serialize(&chain_grand))
        ])],
    )
    .unwrap();
    assert_eq!(chain["package_msg"], "success", "{chain}");
    assert!(ctx
        .mempool
        .as_ref()
        .unwrap()
        .contains(&chain_parent.compute_txid()));
    let pair = dispatch(
        ctx,
        "submitpackage",
        vec![json!([chain_hex, chain_child_hex])],
    )
    .unwrap();
    assert_eq!(pair["package_msg"], "success", "{pair}");

    let mp = ctx.mempool.as_ref().unwrap();
    mp.set_cluster_limits(Some(2), None);
    let (_, cluster_parent) = spend_generated_coinbase(ctx, 1, 50_0000_0000 - 1_000, spk.clone());
    mp.accept_tx(&cluster_parent).expect("parent");
    let cluster_child = child_of(&cluster_parent, 1_000);
    let cluster_grand = child_of(&cluster_child, 1_000);
    let res = dispatch(
        ctx,
        "testmempoolaccept",
        vec![json!([
            hex_encode(serialize(&cluster_child)),
            hex_encode(serialize(&cluster_grand))
        ])],
    )
    .unwrap();
    let arr = res.as_array().expect("package result");
    assert_eq!(arr.len(), 2);
    for row in arr {
        let err = row["package-error"].as_str().expect("package-error");
        assert!(err.contains("too-large-cluster"), "got {row}");
    }
}

#[test]
fn submitpackage_oversized_spk_is_scriptpubkey() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let (ctx, dir, _hub) = ctx_regtest_hub();
    let (parent_hex, parent) = mature_coinbase_spend(
        &ctx,
        50_0000_0000 - 1_000,
        ScriptBuf::from_bytes(vec![0x51]),
    );
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
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![b'a'; 10_001]),
        }],
    };
    let child_hex = hex_encode(serialize(&child));
    let pkg = dispatch(
        &ctx,
        "submitpackage",
        vec![json!([parent_hex, child_hex]), json!(0), json!(1_000)],
    )
    .unwrap();
    assert_eq!(pkg["package_msg"], "transaction failed", "{pkg}");
    let parent_w = hash_hex_display(&parent.compute_wtxid().to_byte_array());
    let child_w = hash_hex_display(&child.compute_wtxid().to_byte_array());
    assert!(
        pkg["tx-results"][&parent_w].get("error").is_none(),
        "parent must admit: {pkg}"
    );
    assert_eq!(
        pkg["tx-results"][&child_w]["error"],
        json!("scriptpubkey"),
        "{pkg}"
    );
    assert!(ctx
        .mempool
        .as_ref()
        .unwrap()
        .contains(&parent.compute_txid()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scantxoutset_range_errors_match_core() {
    let (ctx, dir) = ctx_empty();
    let bad = |range: serde_json::Value| {
        super::descriptor_scan::expand_scan_objects(
            &ctx,
            &[json!({"desc": "desc", "range": range})],
        )
        .unwrap_err()
    };
    let msg = |e: serde_json::Value| e["message"].as_str().unwrap().to_string();
    assert_eq!(msg(bad(json!(-1))), "End of range is too high");
    assert_eq!(
        msg(bad(json!([-1, 10]))),
        "Range should be greater or equal than 0"
    );
    assert_eq!(
        msg(bad(json!([2, 1]))),
        "Range specified as [begin,end] must not have begin after end"
    );
    assert_eq!(msg(bad(json!([0, 1000001]))), "Range is too large");
    let huge = (2i64 << 32) - 1_000_000;
    assert_eq!(
        msg(bad(json!([huge, 2i64 << 32]))),
        "End of range is too high"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scantxoutset_combo_desc_matches_core() {
    let desc = "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/1/1/0)";
    let (ctx, dir) = ctx_empty();
    let scripts = super::descriptor_scan::expand_scan_objects(&ctx, &[json!(desc)]).unwrap();
    let pkh = scripts
        .iter()
        .find(|s| s.desc.starts_with("pkh("))
        .expect("combo expands a pkh");
    assert_eq!(
        pkh.desc,
        "pkh([0c5f9a1e/1/1/0]03e1c5b6e650966971d7e71ef2674f80222752740fc1dfd63bbbd220d2da9bd0fb)#cxmct4w8"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scantxoutset_hardened_wildcard_desc_matches_core() {
    let desc = "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/0h/0h/*)";
    let (ctx, dir) = ctx_empty();
    let obj = json!({"desc": desc, "range": 1});
    let scripts = super::descriptor_scan::expand_scan_objects(&ctx, &[obj]).unwrap();
    let mut pkhs: Vec<&str> = scripts
        .iter()
        .filter(|s| s.desc.starts_with("pkh("))
        .map(|s| s.desc.as_str())
        .collect();
    pkhs.sort();
    assert_eq!(
        pkhs,
        vec![
            "pkh([0c5f9a1e/0h/0h/0]026dbd8b2315f296d36e6b6920b1579ca75569464875c7ebe869b536a7d9503c8c)#rthll0rg",
            "pkh([0c5f9a1e/0h/0h/1]033e6f25d76c00bedb3a8993c7d5739ee806397f0529b1b31dda31ef890f19a60c)#mcjajulr",
        ]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scantxoutset_requires_shindex() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    ctx.query.set_sh_index_enabled(false);
    let desc = "raw(51)";
    dispatch(&ctx, "generatetodescriptor", vec![json!(2), json!(desc)]).unwrap();
    let err = dispatch(&ctx, "scantxoutset", vec![json!("start"), json!([desc])]).unwrap_err();
    assert!(
        err["message"]
            .as_str()
            .unwrap_or("")
            .contains("scripthash index disabled"),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn generate_selects_chained_mempool_parent_first() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_consensus::{pad_empty_from, ChainParams};

    let (ctx, dir, _hub) = ctx_regtest_hub();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let (_tip, _t, cbs) = pad_empty_from(
        ctx.query.as_ref(),
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        101,
        10,
    );
    let cb_txid = cbs[0];
    let cb_val = 50_0000_0000u64;

    let parent = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: cb_txid,
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

    let scan = dispatch(
        &ctx,
        "scantxoutset",
        vec![json!("start"), json!(["raw(51)"])],
    )
    .unwrap();
    let uns = scan["unspents"].as_array().unwrap();
    let cb_hex = hash_hex_display(&cb_txid.to_byte_array());
    assert!(
        uns.iter().all(|u| u["txid"] != json!(cb_hex)),
        "spent coinbase must drop from scan: {scan}"
    );
    assert!(uns.iter().any(|u| u["coinbase"] == false));

    let immature_txid = cbs[9];
    let bad = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: immature_txid,
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
    assert_eq!(genesis["utxo_increase_actual"], 0);
    assert!(genesis.get("utxo_size_inc").is_none());
    assert!(genesis.get("utxo_size_inc_actual").is_none());

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
    ctx.query.store().reset_tx_full_gets();
    let v1 = dispatch(&ctx, "getblock", vec![tip_hash.clone(), json!(1)]).unwrap();
    assert!(
        ctx.query.store().tx_full_gets().is_empty(),
        "verbosity 1 2-tx block: {:?}",
        ctx.query.store().tx_full_gets()
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
    assert_eq!(got["utxo_increase"], got["outs"].as_i64().unwrap() - 1);
    assert_eq!(
        got["utxo_increase_actual"].as_i64(),
        Some(got["utxo_increase"].as_i64().unwrap() - 1)
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
fn prune_life_blockstats(ctx: &RpcContext) {
    use rbitcoin_store::TxStatRow;
    let genesis = dispatch(ctx, "getblockstats", vec![json!(0)]).unwrap();
    assert_eq!(genesis["ins"], 0);
    assert_eq!(genesis["outs"], 1);
    assert_eq!(genesis["txs"], 1);
    assert_eq!(genesis["total_size"], 0);
    assert_eq!(genesis["utxo_increase"], 1);
    assert_eq!(genesis["utxo_increase_actual"], 0);
    dispatch(ctx, "generate", vec![json!(2)]).unwrap();
    let got = dispatch(ctx, "getblockstats", vec![json!(1)]).unwrap();
    assert_eq!(got["txs"], 1);
    assert_eq!(got["ins"], 0);
    assert_eq!(got["outs"], 1);
    assert_eq!(got["utxo_increase"], 1);
    assert_eq!(got["utxo_increase_actual"], 1, "{got}");
    assert_eq!(got["total_size"], 0);
    assert_eq!(got["swtxs"], 0);
    assert!(got.get("utxo_size_inc").is_none(), "{got}");
    let e = dispatch(
        ctx,
        "getblockstats",
        vec![json!(1), json!(["utxo_size_inc"])],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert_eq!(e["message"], "Invalid selected statistic 'utxo_size_inc'");
    let fk = ctx.query.block_tx_fks(Height(0)).unwrap()[0];
    ctx.query
        .store()
        .write_txstat_row(
            fk,
            &TxStatRow {
                fee_sat: 0,
                base: 0,
                wit_extra: 0,
            },
        )
        .unwrap();
    assert!(ctx.query.stamped_txstat_block(Height(0)).unwrap().is_none());
    let restamped = dispatch(ctx, "getblockstats", vec![json!(0)]).unwrap();
    assert_eq!(restamped["txs"], 1);
    assert!(ctx.query.stamped_txstat_block(Height(0)).unwrap().is_some());
}

fn prune_life_getblock(ctx: &RpcContext) {
    let genesis_hash = dispatch(ctx, "getblockhash", vec![json!(0)]).unwrap();
    let _ = ctx.query.sample_reset_reconstruct_archived();
    ctx.query.set_pruneheight(Some(Height(0))).unwrap();
    let info = dispatch(ctx, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(info["pruned"], true);
    assert_eq!(info["pruneheight"], 0);
    let err = dispatch(ctx, "getblock", vec![genesis_hash.clone(), json!(0)]).unwrap_err();
    assert_eq!(err["code"], json!(-8));
    assert!(err["message"].as_str().unwrap().contains("pruned"), "{err}");
    let v1 = dispatch(ctx, "getblock", vec![genesis_hash.clone(), json!(1)]).unwrap();
    assert_eq!(v1["tx"].as_array().unwrap().len(), 1);
    let err2 = dispatch(ctx, "getblock", vec![genesis_hash, json!(2)]).unwrap_err();
    assert_eq!(err2["code"], json!(-8));
    let rerr = dispatch(ctx, "getrawtransaction", vec![v1["tx"][0].clone()]).unwrap_err();
    assert_eq!(
        rerr["code"], ERR_INVALID_ADDRESS_OR_KEY,
        "genesis first: {rerr}"
    );
    let net = dispatch(ctx, "getnetworkinfo", vec![]).unwrap();
    let names: Vec<&str> = net["localservicesnames"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(names.contains(&"NETWORK_LIMITED"), "{names:?}");
    assert!(!names.contains(&"NETWORK"), "{names:?}");
    let stats = dispatch(ctx, "getblockstats", vec![json!(0)]).unwrap();
    assert_eq!(stats["txs"], 1);
    assert_eq!(stats["outs"], 1);
    assert_eq!(ctx.query.sample_reset_reconstruct_archived(), 0);
    ctx.query.set_pruneheight(Some(Height(1))).unwrap();
    let h1 = dispatch(ctx, "getblockhash", vec![json!(1)]).unwrap();
    let b1 = dispatch(ctx, "getblock", vec![h1, json!(1)]).unwrap();
    let rerr = dispatch(ctx, "getrawtransaction", vec![b1["tx"][0].clone()]).unwrap_err();
    assert_eq!(rerr["code"], json!(-8), "{rerr}");
}

#[test]
fn pruned_seqsigwit_life() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    prune_life_blockstats(&ctx);
    prune_life_getblock(&ctx);
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
fn getnetworkinfo_localaddresses_from_externalip() {
    use rbitcoin_net::PeerHub;
    use std::net::{IpAddr, Ipv4Addr};

    let (mut ctx, dir) = ctx_empty();
    let hub = PeerHub::new();
    hub.set_listen_port(18445);
    hub.set_external_ips(vec![IpAddr::V4(Ipv4Addr::new(42, 42, 42, 42))]);
    ctx.peers = Some(hub);
    let info = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    let addrs = info["localaddresses"].as_array().expect("array");
    assert_eq!(addrs.len(), 1, "{info}");
    assert_eq!(addrs[0]["address"], "42.42.42.42");
    assert_eq!(addrs[0]["port"], 18445);
    assert_eq!(addrs[0]["score"], 4);
    ctx.peers.as_ref().unwrap().set_discover(false);
    let info = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    let addrs = info["localaddresses"].as_array().expect("array");
    assert!(addrs.is_empty(), "no-discover localaddresses: {info}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getnetworkinfo_includes_electrum_onion() {
    use rbitcoin_net::PeerHub;

    let (mut ctx, dir) = ctx_empty();
    let hub = PeerHub::new();
    hub.set_discover(false);
    hub.set_wallet_onion(
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion".into(),
        50001,
    );
    hub.set_wallet_onion(
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabce.onion".into(),
        3000,
    );
    ctx.peers = Some(hub);
    let info = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    let addrs = info["localaddresses"].as_array().expect("array");
    assert_eq!(addrs.len(), 2, "{info}");
    assert_eq!(
        addrs[0]["address"],
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion"
    );
    assert_eq!(addrs[0]["port"], 50001);
    assert_eq!(addrs[1]["port"], 3000);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getnetworkinfo_includes_p2p_onion() {
    use rbitcoin_net::PeerHub;

    let (mut ctx, dir) = ctx_empty();
    let hub = PeerHub::new();
    hub.set_discover(false);
    hub.set_p2p_onion(
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion".into(),
        18444,
    );
    ctx.peers = Some(hub);
    let info = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    let addrs = info["localaddresses"].as_array().expect("array");
    assert_eq!(addrs.len(), 1, "{info}");
    assert_eq!(
        addrs[0]["address"],
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"
    );
    assert_eq!(addrs[0]["port"], 18444);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getnetworkinfo_includes_p2p_i2p() {
    use rbitcoin_net::{NetAddr, PeerHub};

    let (mut ctx, dir) = ctx_empty();
    let hub = PeerHub::new();
    hub.set_discover(false);
    let i2p = NetAddr::I2p {
        dest: [0x11; 32],
        port: 0,
    };
    hub.set_p2p_i2p(i2p);
    ctx.peers = Some(hub);
    let info = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    let addrs = info["localaddresses"].as_array().expect("array");
    assert_eq!(addrs.len(), 1, "{info}");
    assert_eq!(addrs[0]["address"], i2p.host_str());
    assert_eq!(addrs[0]["port"], 0);
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
    assert_eq!(dispatch(&ctx, "getpeerinfo", vec![]).unwrap(), json!([]));
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
    assert!(arr[0].get("mapped_as").is_none());
    let mut t = rbitcoin_net::NetPermTable::default();
    let g = rbitcoin_net::parse_whitelist("relay,out@127.0.0.1").unwrap();
    t.whitelist.push(g);
    hub.set_net_perms(t);
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
    let pi = dispatch(&ctx, "getpeerinfo", vec![]).unwrap();
    assert_eq!(pi[0]["bytesrecv"].as_u64().unwrap(), mid);
    assert_eq!(pi[0]["bytessent"].as_u64().unwrap(), 0);
    assert_eq!(pi[0]["last_inv_sequence"].as_u64().unwrap(), 1);
    assert_eq!(pi[0]["inv_to_send"].as_u64().unwrap(), 0);

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

fn test_version(
    timestamp: i64,
    start_height: i32,
) -> bitcoin::p2p::message_network::VersionMessage {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445);
    VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::P2P_V2,
        timestamp,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&bind, ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:0.1.0(testnode0)/".into(),
        start_height,
        relay: true,
    }
}

#[test]
fn getpeerinfo_connecting_has_unknown_sync_and_zero_offset() {
    use bitcoin::hashes::Hash;
    use rbitcoin_net::{PeerConnType, PeerHub};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let (mut ctx, dir) = ctx_empty();
    let hub = PeerHub::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445);
    let live = hub.register_connecting(addr, bind, false, PeerConnType::OutboundFullRelay);
    live.note_best_known(bitcoin::BlockHash::from_byte_array([0xab; 32]));
    ctx.peers = Some(hub);
    let r = dispatch(&ctx, "getpeerinfo", vec![]).unwrap();
    let row = &r.as_array().unwrap()[0];
    assert_eq!(row["synced_headers"], json!(-1));
    assert_eq!(row["synced_blocks"], json!(-1));
    assert_eq!(row["timeoffset"], json!(0));
    assert_eq!(row["startingheight"], json!(-1));
    let net = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    assert_eq!(net["timeoffset"], json!(0));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getpeerinfo_synced_heights_from_best_known() {
    use bitcoin::hashes::Hash;
    use rbitcoin_net::{PeerConnType, PeerHub};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let (mut ctx, dir, chain) = ctx_regtest_hub();
    let genesis = chain.tip_hash().expect("genesis");
    let hub = PeerHub::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445);
    let live = hub.register(
        addr,
        bind,
        &test_version(0, 0),
        false,
        PeerConnType::OutboundFullRelay,
    );
    live.note_best_known(genesis);
    ctx.peers = Some(hub.clone());
    let r = dispatch(&ctx, "getpeerinfo", vec![]).unwrap();
    let row = &r.as_array().unwrap()[0];
    assert_eq!(row["synced_headers"], json!(0));
    assert_eq!(row["synced_blocks"], json!(0));

    live.note_best_known(bitcoin::BlockHash::from_byte_array([0xab; 32]));
    let r = dispatch(&ctx, "getpeerinfo", vec![]).unwrap();
    let row = &r.as_array().unwrap()[0];
    assert_eq!(row["synced_headers"], json!(-1));
    assert_eq!(row["synced_blocks"], json!(-1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getpeerinfo_synced_heights_via_query_without_chain() {
    use rbitcoin_net::{PeerConnType, PeerHub};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let (mut ctx, dir, chain) = ctx_regtest_hub();
    let genesis = chain.tip_hash().expect("genesis");
    ctx.chain = None;
    let hub = PeerHub::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445);
    let live = hub.register(
        addr,
        bind,
        &test_version(0, 0),
        false,
        PeerConnType::OutboundFullRelay,
    );
    live.note_best_known(genesis);
    ctx.peers = Some(hub);
    let r = dispatch(&ctx, "getpeerinfo", vec![]).unwrap();
    let row = &r.as_array().unwrap()[0];
    assert_eq!(row["synced_headers"], json!(0));
    assert_eq!(row["synced_blocks"], json!(0));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getpeerinfo_header_only_best_known_is_not_synced_blocks() {
    use bitcoin::consensus::encode::serialize;
    use rbitcoin_consensus::mine_regtest_paying;
    use rbitcoin_net::{PeerConnType, PeerHub};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let (mut ctx, dir, chain) = ctx_regtest_hub();
    let (_, script) = p2wpkh_regtest();
    let prev = chain.tip_hash().unwrap();
    let time = chain.tip_header().unwrap().time + 1;
    let child = mine_regtest_paying(prev, time, 1, script, vec![]);
    let hex = rbitcoin_primitives::hex_encode(serialize(&child));
    dispatch(&ctx, "submitheader", vec![json!(hex)]).unwrap();
    let hub = PeerHub::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445);
    let live = hub.register(
        addr,
        bind,
        &test_version(0, 0),
        false,
        PeerConnType::OutboundFullRelay,
    );
    live.note_best_known(child.block_hash());
    ctx.peers = Some(hub);
    let r = dispatch(&ctx, "getpeerinfo", vec![]).unwrap();
    let row = &r.as_array().unwrap()[0];
    assert_eq!(row["synced_headers"], json!(1));
    assert_eq!(row["synced_blocks"], json!(-1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getpeerinfo_and_getnetworkinfo_timeoffset_from_version() {
    use rbitcoin_net::{PeerConnType, PeerHub};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let (mut ctx, dir) = ctx_empty();
    let hub = PeerHub::new();
    hub.set_mock_now(1_700_000_000);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445);
    hub.register(
        addr,
        bind,
        &test_version(1_700_000_060, 0),
        false,
        PeerConnType::OutboundFullRelay,
    );
    let inbound_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18500);
    hub.register(
        inbound_addr,
        bind,
        &test_version(1_700_000_099, 0),
        true,
        PeerConnType::Inbound,
    );
    ctx.peers = Some(hub);
    let r = dispatch(&ctx, "getpeerinfo", vec![]).unwrap();
    let arr = r.as_array().unwrap();
    let out = arr.iter().find(|p| p["inbound"] == false).unwrap();
    let inn = arr.iter().find(|p| p["inbound"] == true).unwrap();
    assert_eq!(out["timeoffset"], json!(60));
    assert_eq!(inn["timeoffset"], json!(99));
    let net = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    assert_eq!(
        net["timeoffset"],
        json!(60),
        "getnetworkinfo.timeoffset is outbound median, not inbound"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getnetworkinfo_timeoffset_median_of_outbound() {
    use rbitcoin_net::{PeerConnType, PeerHub};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let (mut ctx, dir) = ctx_empty();
    let hub = PeerHub::new();
    hub.set_mock_now(1_700_000_000);
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445);
    for (i, offset) in [10i64, 20, 40].into_iter().enumerate() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19000 + i as u16);
        hub.register(
            addr,
            bind,
            &test_version(1_700_000_000 + offset, 0),
            false,
            PeerConnType::OutboundFullRelay,
        );
    }
    ctx.peers = Some(hub);
    let net = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    assert_eq!(net["timeoffset"], json!(20));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getpeerinfo_timeoffset_when_peer_clock_behind() {
    use rbitcoin_net::{PeerConnType, PeerHub};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let (mut ctx, dir) = ctx_empty();
    let hub = PeerHub::new();
    hub.set_mock_now(1_700_000_000);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445);
    hub.register(
        addr,
        bind,
        &test_version(1_699_999_940, 0),
        false,
        PeerConnType::OutboundFullRelay,
    );
    ctx.peers = Some(hub);
    let r = dispatch(&ctx, "getpeerinfo", vec![]).unwrap();
    assert_eq!(r.as_array().unwrap()[0]["timeoffset"], json!(-60));
    let net = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    assert_eq!(net["timeoffset"], json!(-60));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getnetworkinfo_timeoffset_even_n_and_inbound_only() {
    use rbitcoin_net::{PeerConnType, PeerHub};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let (mut ctx, dir) = ctx_empty();
    let hub = PeerHub::new();
    hub.set_mock_now(1_700_000_000);
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445);
    for (i, offset) in [10i64, 20].into_iter().enumerate() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19100 + i as u16);
        hub.register(
            addr,
            bind,
            &test_version(1_700_000_000 + offset, 0),
            false,
            PeerConnType::OutboundFullRelay,
        );
    }
    ctx.peers = Some(hub);
    let net = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    assert_eq!(net["timeoffset"], json!(20), "even N uses upper middle");

    let (mut ctx, dir2) = ctx_empty();
    let hub = PeerHub::new();
    hub.set_mock_now(1_700_000_000);
    hub.register(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18500),
        bind,
        &test_version(1_700_000_099, 0),
        true,
        PeerConnType::Inbound,
    );
    ctx.peers = Some(hub);
    let net = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    assert_eq!(net["timeoffset"], json!(0), "inbound-only median is 0");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

#[test]
fn getpeerinfo_sent_pingwait_and_limited_services() {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use rbitcoin_net::{PeerConnType, PeerHub, PingAction};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let (mut ctx, dir) = ctx_empty();
    let hub = PeerHub::new();
    hub.set_mock_now(1_700_000_000);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445);
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS | ServiceFlags::P2P_V2,
        timestamp: 1_700_000_000,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&bind, ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:0.1.0(testnode0)/".into(),
        start_height: 0,
        relay: true,
    };
    let live = hub.register(addr, bind, &ver, false, PeerConnType::OutboundFullRelay);
    live.note_sent("version", 100);
    let PingAction::Send { nonce } = live.take_ping_action(hub.now_secs()).unwrap() else {
        panic!("expected ping send");
    };
    ctx.peers = Some(hub.clone());
    let info = dispatch(&ctx, "getpeerinfo", vec![]).unwrap();
    let row = &info.as_array().unwrap()[0];
    assert!(row["bytessent_per_msg"]["version"].as_u64().unwrap() >= 124);
    assert!(row.get("pingwait").is_some(), "{row}");
    let names = row["servicesnames"].as_array().unwrap();
    assert!(names.iter().any(|n| n == "NETWORK_LIMITED"), "{names:?}");

    assert!(live.on_pong(&nonce.to_le_bytes(), 1_700_000_029).is_none());
    hub.set_mock_now(1_700_000_029);
    let info = dispatch(&ctx, "getpeerinfo", vec![]).unwrap();
    let row = &info.as_array().unwrap()[0];
    assert_eq!(row["pingtime"], json!(29.0));
    assert_eq!(row["minping"], json!(29.0));
    hub.set_noban(true);
    let info = dispatch(&ctx, "getpeerinfo", vec![]).unwrap();
    assert_eq!(
        info.as_array().unwrap()[0]["permissions"],
        json!([]),
        "hub --trusted does not grant getpeerinfo.permissions"
    );
    let mut t = rbitcoin_net::NetPermTable::default();
    t.whitelist
        .push(rbitcoin_net::parse_whitelist("noban,out@127.0.0.1").expect("whitelist"));
    hub.set_net_perms(t);
    let info = dispatch(&ctx, "getpeerinfo", vec![]).unwrap();
    assert_eq!(
        info.as_array().unwrap()[0]["permissions"],
        json!(["noban", "download"])
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getpeerinfo_mapped_as_when_asmap() {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use rbitcoin_net::{AsMap, PeerConnType, PeerHub, TWO_PREFIX_ASMAP};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    let (mut ctx, dir) = ctx_empty();
    let hub = PeerHub::new();
    hub.set_asmap(Some(Arc::new(
        AsMap::from_bytes(TWO_PREFIX_ASMAP.to_vec()).expect("fixture"),
    )));
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 18444);
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
    let _live = hub.register(addr, bind, &ver, false, PeerConnType::OutboundFullRelay);
    ctx.peers = Some(hub);
    let r = dispatch(&ctx, "getpeerinfo", vec![]).unwrap();
    assert_eq!(r.as_array().unwrap()[0]["mapped_as"], json!(1));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Every `P2PNode` attaches a dialer, so no session reaches this arm.
/// `node_run_p2p_short` owns the connected `addnode` / `disconnectnode` results.
#[test]
fn addnode_without_a_dialer_errors() {
    use rbitcoin_net::PeerHub;
    let (mut ctx, dir) = ctx_empty();
    let hub = PeerHub::new();
    ctx.peers = Some(hub);
    let e = dispatch(&ctx, "addnode", vec![json!("127.0.0.1:1"), json!("onetry")]).unwrap_err();
    assert!(e["message"].as_str().unwrap().contains("dialer"), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getpeerinfo_and_disconnectnode_support_onion_addr() {
    use rbitcoin_net::{PeerConnType, PeerHub};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let (mut ctx, dir) = ctx_empty();
    let hub = PeerHub::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445);
    let onion: rbitcoin_net::NetAddr =
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
            .parse()
            .unwrap();
    hub.register_net(
        addr,
        onion,
        bind,
        &test_version(0, 0),
        false,
        PeerConnType::OutboundFullRelay,
    );
    ctx.peers = Some(hub);

    let r = dispatch(&ctx, "getpeerinfo", vec![]).unwrap();
    let row = &r.as_array().unwrap()[0];
    assert_eq!(
        row["addr"],
        json!("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333")
    );
    assert_eq!(row["network"], json!("onion"));
    dispatch(
        &ctx,
        "disconnectnode",
        vec![json!(
            "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
        )],
    )
    .unwrap();
    assert_eq!(dispatch(&ctx, "getpeerinfo", vec![]).unwrap(), json!([]));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn addpeeraddress_updates_addrman_without_rewriting_peers_file() {
    use rbitcoin_net::AddrMan;
    use std::sync::Mutex;

    let (mut ctx, dir) = ctx_empty();
    let peers_path = dir.join("peers");
    let am = Arc::new(Mutex::new(AddrMan::new()));
    ctx.addrman = Some(Arc::clone(&am));

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
    assert!(
        !peers_path.exists(),
        "addpeeraddress must not rewrite peers on every call"
    );

    let named = RpcParams::named(
        json!({"address": "129.0.0.1", "port": 8334, "tried": false})
            .as_object()
            .unwrap()
            .clone(),
    );
    let out = dispatch(&ctx, "addpeeraddress", named).unwrap();
    assert_eq!(out, json!({"success": true}));
    assert_eq!(am.lock().unwrap().len(), 2);
    assert!(!peers_path.exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getnodeaddresses_empty_named_filter_and_count() {
    use rbitcoin_net::AddrMan;
    use std::sync::Mutex;

    let (ctx, dir) = ctx_empty();
    assert_eq!(
        dispatch(&ctx, "getnodeaddresses", vec![]).unwrap(),
        json!([])
    );
    let bad_net = dispatch(&ctx, "getnodeaddresses", vec![json!(1), json!("notanet")]).unwrap_err();
    assert_eq!(bad_net["code"], ERR_INVALID_PARAMETER);
    let neg = dispatch(&ctx, "getnodeaddresses", vec![json!(-1)]).unwrap_err();
    assert_eq!(neg["code"], ERR_INVALID_PARAMETER);
    let not_int = dispatch(&ctx, "getnodeaddresses", vec![json!("x")]).unwrap_err();
    assert_eq!(not_int["code"], ERR_INVALID_PARAMS);
    let _ = std::fs::remove_dir_all(&dir);

    let (mut ctx, dir) = ctx_empty();
    let am = Arc::new(Mutex::new(AddrMan::new()));
    ctx.addrman = Some(Arc::clone(&am));
    dispatch(
        &ctx,
        "addpeeraddress",
        vec![json!("128.1.2.3"), json!(8333)],
    )
    .unwrap();
    dispatch(&ctx, "addpeeraddress", vec![json!("::1"), json!(8333)]).unwrap();
    let none = dispatch(&ctx, "getnodeaddresses", vec![]).unwrap();
    assert_eq!(none.as_array().unwrap().len(), 1);
    let all = dispatch(&ctx, "getnodeaddresses", vec![json!(0)]).unwrap();
    assert_eq!(all.as_array().unwrap().len(), 2);
    let v4 = dispatch(&ctx, "getnodeaddresses", vec![json!(10), json!("ipv4")]).unwrap();
    assert_eq!(v4.as_array().unwrap().len(), 1);
    assert_eq!(v4[0]["network"], "ipv4");
    let v6 = dispatch(
        &ctx,
        "getnodeaddresses",
        named(json!({"count": 0, "network": "ipv6"})),
    )
    .unwrap();
    assert_eq!(v6.as_array().unwrap().len(), 1);
    assert_eq!(v6[0]["network"], "ipv6");
    let onion = dispatch(&ctx, "getnodeaddresses", vec![json!(0), json!("onion")]).unwrap();
    assert_eq!(onion.as_array().unwrap().len(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rpc_honesty_mempool_budget_and_network_identity() {
    let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-honest").expect("temp dir");
    let q = Arc::new(Query::open_or_create_tiny(dir.join("store")).unwrap());
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

        logpath: String::new(),
        active: std::sync::Arc::new(std::sync::Mutex::new(RpcActive::default())),

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
    // Core 0.19 CLIENT_VERSION. Below this, bitcoincore-rpc requires the
    // pre-0.19 bip9_softforks map and rejects our getblockchaininfo.
    assert_eq!(net["version"].as_u64(), Some(190_000), "{net}");
    assert_eq!(
        net["protocolversion"].as_u64(),
        Some(70016),
        "P2P nVersion stays 70016; version is the RPC shape floor"
    );
    assert_ne!(
        net["version"].as_u64(),
        Some(799),
        "crate semver packing must not be getnetworkinfo.version"
    );
    assert_eq!(
        net["subversion"].as_str().unwrap(),
        rbitcoin_primitives::rbitcoin_subversion(env!("CARGO_PKG_VERSION"), &[] as &[&str],)
            .unwrap()
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

#[test]
fn testmempoolaccept_missing_inputs_is_missing_inputs() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    let (ctx, dir) = ctx_empty();
    let tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0x11; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let hex = hex_encode(serialize(&tx));
    let row = dispatch(&ctx, "testmempoolaccept", vec![json!([hex])]).unwrap();
    assert_eq!(row[0]["allowed"], json!(false), "{row}");
    assert_eq!(row[0]["reject-reason"], json!("missing-inputs"), "{row}");
    assert_eq!(ctx.mempool.as_ref().unwrap().orphan_count(), 0);

    ctx.mempool.as_ref().unwrap().accept_tx(&tx).unwrap_err();
    assert_eq!(ctx.mempool.as_ref().unwrap().orphan_count(), 1);
    let row = dispatch(&ctx, "testmempoolaccept", vec![json!([hex])]).unwrap();
    assert_eq!(row[0]["allowed"], json!(false), "{row}");
    assert_eq!(row[0]["reject-reason"], json!("missing-inputs"), "{row}");
    assert_eq!(ctx.mempool.as_ref().unwrap().orphan_count(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[allow(clippy::cognitive_complexity)] // one fixture, many decode arms
#[test]
fn decode_rpc_subset() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize_hex;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    let (ctx, dir) = ctx_empty();
    let help = dispatch(&ctx, "help", vec![]).unwrap();
    let help_text = help.as_str().unwrap();
    for name in ["decoderawtransaction", "decodescript", "validateaddress"] {
        assert!(help_text.lines().any(|l| l == name), "help missing {name}");
    }

    let script_sig = ScriptBuf::from_bytes(vec![0x51]);
    let legacy = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1; 32]),
                vout: 0,
            },
            script_sig: script_sig.clone(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let legacy_hex = serialize_hex(&legacy);
    let dec = dispatch(&ctx, "decoderawtransaction", vec![json!(legacy_hex)]).unwrap();
    assert_eq!(dec["version"], json!(2));
    assert_eq!(dec["vin"][0]["vout"], json!(0));
    assert_eq!(
        dec["vin"][0]["scriptSig"]["hex"],
        json!(rbitcoin_primitives::hex_encode(script_sig.as_bytes()))
    );
    assert!(dec["vin"][0]["scriptSig"]["asm"]
        .as_str()
        .unwrap()
        .contains("1"));
    assert_eq!(dec["vout"][0]["scriptPubKey"]["type"], json!("nonstandard"));
    assert!(dec["size"].as_u64().unwrap() > 0);
    assert!(dec["weight"].as_u64().unwrap() > 0);
    assert!(dec.get("vin").unwrap()[0].get("txinwitness").is_none());

    let extra = dispatch(
        &ctx,
        "decoderawtransaction",
        vec![json!(format!("{legacy_hex}00"))],
    )
    .unwrap_err();
    assert_eq!(extra["code"], ERR_DESERIALIZATION);
    assert_eq!(extra["message"], json!("TX decode failed"));

    let mut wit = Witness::new();
    wit.push([0xAAu8]);
    let witness_tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([2; 32]),
                vout: 1,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: wit,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let wit_hex = serialize_hex(&witness_tx);
    let wit_ok = dispatch(
        &ctx,
        "decoderawtransaction",
        vec![json!(wit_hex.clone()), json!(true)],
    )
    .unwrap();
    assert_eq!(wit_ok["vin"][0]["txinwitness"], json!(["aa"]));
    let wit_forced = dispatch(
        &ctx,
        "decoderawtransaction",
        vec![json!(wit_hex), json!(false)],
    )
    .unwrap_err();
    assert_eq!(wit_forced["code"], ERR_DESERIALIZATION);
    assert_eq!(wit_forced["message"], json!("TX decode failed"));

    let p2wpkh = Address::from_str("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")
        .unwrap()
        .require_network(BtcNetwork::Regtest)
        .unwrap();
    let spk_hex = rbitcoin_primitives::hex_encode(p2wpkh.script_pubkey().as_bytes());
    let script = dispatch(&ctx, "decodescript", vec![json!(spk_hex.clone())]).unwrap();
    assert_eq!(script["type"], json!("witness_v0_keyhash"));
    assert_eq!(script["address"], json!(p2wpkh.to_string()));
    assert_eq!(script["hex"], json!(spk_hex));
    assert!(script.get("p2sh").is_none());
    assert!(script.get("segwit").is_none());
    assert!(script.get("desc").is_none());

    let op_true = dispatch(&ctx, "decodescript", vec![json!("51")]).unwrap();
    assert_eq!(op_true["type"], json!("nonstandard"));
    assert!(op_true.get("address").is_none());

    let valid = dispatch(&ctx, "validateaddress", vec![json!(p2wpkh.to_string())]).unwrap();
    assert_eq!(valid["isvalid"], json!(true));
    assert_eq!(valid["address"], json!(p2wpkh.to_string()));
    assert_eq!(valid["scriptPubKey"], json!(spk_hex));
    assert_eq!(valid["isscript"], json!(false));
    assert_eq!(valid["iswitness"], json!(true));
    assert_eq!(valid["witness_version"], json!(0));
    assert!(valid["witness_program"].as_str().unwrap().len() == 40);
    assert!(valid.get("error_locations").is_none());

    let p2sh = dispatch(
        &ctx,
        "validateaddress",
        vec![json!("2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc")],
    )
    .unwrap();
    assert_eq!(p2sh["isvalid"], json!(true));
    assert_eq!(p2sh["isscript"], json!(true));
    assert_eq!(p2sh["iswitness"], json!(false));

    let junk = dispatch(&ctx, "validateaddress", vec![json!("not-an-address")]).unwrap();
    assert_eq!(junk, json!({"isvalid": false}));

    let mainnet = dispatch(
        &ctx,
        "validateaddress",
        vec![json!("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")],
    )
    .unwrap();
    assert_eq!(mainnet, json!({"isvalid": false}));

    let p2tr_spk = ScriptBuf::from_bytes(
        rbitcoin_primitives::hex_decode(
            "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap(),
    );
    let p2tr = Address::from_script(&p2tr_spk, BtcNetwork::Regtest).expect("p2tr address");
    let tr = dispatch(&ctx, "validateaddress", vec![json!(p2tr.to_string())]).unwrap();
    assert_eq!(tr["isscript"], json!(true), "{tr}");
    assert_eq!(tr["iswitness"], json!(true));
    assert_eq!(tr["witness_version"], json!(1));

    let p2a_spk = ScriptBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73]);
    let p2a = Address::from_script(&p2a_spk, BtcNetwork::Regtest).expect("p2a address");
    let anchor = dispatch(&ctx, "validateaddress", vec![json!(p2a.to_string())]).unwrap();
    assert_eq!(anchor["isscript"], json!(true), "{anchor}");
    assert_eq!(anchor["iswitness"], json!(true));
    assert!(anchor.get("witness_version").is_none(), "{anchor}");
    assert!(anchor.get("witness_program").is_none(), "{anchor}");

    let still_never = dispatch(&ctx, "createrawtransaction", vec![]).unwrap_err();
    assert_eq!(still_never["code"], ERR_METHOD_NOT_FOUND);
    let _ = std::fs::remove_dir_all(&dir);
}

#[allow(clippy::cognitive_complexity)] // table of RpcParams coercions
#[test]
fn rpc_params_type_coercion_and_unknown_named() {
    let p = RpcParams::positional(vec![json!("abc"), json!(7), json!(true)]);
    assert_eq!(p.req_str(0, "hexstring").unwrap(), "abc");
    assert_eq!(p.req_u64(1, "n").unwrap(), 7);
    assert_eq!(p.opt_bool(2, "flag").unwrap(), Some(true));
    assert_eq!(p.opt_str(3, "missing").unwrap(), None);
    assert_eq!(p.opt_u64(3, "missing").unwrap(), None);
    assert_eq!(p.opt_bool(3, "missing").unwrap(), None);

    let e = p.req_str(1, "hexstring").unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMS);
    assert!(e["message"].as_str().unwrap().contains("must be a string"));
    let e = p.req_u64(0, "n").unwrap_err();
    assert!(e["message"]
        .as_str()
        .unwrap()
        .contains("must be an integer"));
    let e = p.req(9, "height").unwrap_err();
    assert!(e["message"].as_str().unwrap().contains("height required"));

    let nulls = RpcParams::positional(vec![Value::Null]);
    assert_eq!(nulls.opt_str(0, "x").unwrap(), None);
    assert_eq!(nulls.opt_u64(0, "x").unwrap(), None);
    assert_eq!(nulls.opt_bool(0, "x").unwrap(), None);
    let e = nulls.req_str(0, "hexstring").unwrap_err();
    assert!(e["message"].as_str().unwrap().contains("must be a string"));

    let bad_opt = RpcParams::positional(vec![json!("nope")]);
    assert!(bad_opt.opt_u64(0, "n").unwrap_err()["message"]
        .as_str()
        .unwrap()
        .contains("must be an integer"));
    assert!(bad_opt.opt_bool(0, "flag").unwrap_err()["message"]
        .as_str()
        .unwrap()
        .contains("must be a bool"));
    assert!(bad_opt.opt_str(0, "s").unwrap().is_some());

    let extra = RpcParams::named(
        json!({"blockhash": "aa", "foo": 1})
            .as_object()
            .cloned()
            .unwrap(),
    );
    let e = extra.reject_unknown(&["blockhash"]).unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert!(e["message"]
        .as_str()
        .unwrap()
        .contains("Unknown named parameter foo"));
    extra.reject_unknown(&["blockhash", "foo"]).unwrap();
    RpcParams::positional(vec![json!(1)])
        .reject_unknown(&[])
        .unwrap();

    let mixed = RpcParams::named(
        json!({"args": ["from-args"], "verbose": true})
            .as_object()
            .cloned()
            .unwrap(),
    );
    assert!(
        mixed.get(0, "hexstring").is_none(),
        "args peel is echo-only, not RpcParams::named"
    );
    assert_eq!(mixed.opt_bool(1, "verbose").unwrap(), Some(true));
    assert_eq!(
        mixed
            .get(0, "args")
            .and_then(|v| v.as_array())
            .map(|a| a[0].as_str()),
        Some(Some("from-args"))
    );

    let args_not_array = RpcParams::named(
        json!({"args": "not-array", "blockhash": "aa"})
            .as_object()
            .cloned()
            .unwrap(),
    );
    assert_eq!(args_not_array.req_str(0, "blockhash").unwrap(), "aa");

    assert_eq!(json_u64(&json!(0)), Some(0));
    assert_eq!(json_u64(&json!(-1)), None);
    assert_eq!(json_i64(&json!(-1)), Some(-1));
    assert_eq!(json_i64(&json!(u64::MAX)), None);

    assert_eq!(
        opt_verbosity(&RpcParams::positional(vec![json!(true)]), 0, "verbosity").unwrap(),
        1
    );
    assert_eq!(
        opt_verbosity(&RpcParams::positional(vec![json!(false)]), 0, "verbosity").unwrap(),
        0
    );
    assert_eq!(
        opt_verbosity(&RpcParams::positional(vec![json!(2)]), 0, "verbosity").unwrap(),
        2
    );
    assert_eq!(
        opt_verbosity(&RpcParams::empty(), 0, "verbosity").unwrap(),
        1
    );
    assert!(
        opt_verbosity(&RpcParams::positional(vec![json!("nope")]), 0, "verbosity").unwrap_err()
            ["message"]
            .as_str()
            .unwrap()
            .contains("must be an integer")
    );
}

#[test]
fn every_listed_method_rejects_unknown_named_param() {
    let (ctx, dir) = ctx_empty();
    let info = dispatch(&ctx, "getrpcinfo", vec![]).unwrap();
    let listed = info["methods"].as_array().unwrap();
    assert!(listed.len() >= 50, "catalog shrank: {}", listed.len());
    for name in listed.iter().filter_map(|v| v.as_str()) {
        let err = dispatch(&ctx, name, named(json!({"not_a_real_rpc_param": 1}))).unwrap_err();
        assert_eq!(err["code"], ERR_INVALID_PARAMETER, "{name}: {err}");
        assert!(
            err["message"]
                .as_str()
                .unwrap()
                .contains("Unknown named parameter not_a_real_rpc_param"),
            "{name}: {err}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[allow(clippy::cognitive_complexity)] // one empty store, every required-arg type gate
#[test]
fn dispatch_wrong_json_types_are_param_errors() {
    let (ctx, dir) = ctx_empty();
    for (method, params, needle) in [
        ("help", vec![json!(1)], "command must be a string"),
        ("getblockhash", vec![json!("0")], "must be an integer"),
        ("getblockheader", vec![json!(1)], "must be a string"),
        ("getblock", vec![json!(true)], "must be a string"),
        ("getrawtransaction", vec![json!([])], "must be a string"),
        ("decoderawtransaction", vec![json!(0)], "must be a string"),
        ("decodescript", vec![json!(false)], "must be a string"),
        ("validateaddress", vec![json!(1)], "must be a string"),
        ("sendrawtransaction", vec![json!(1)], "must be a string"),
        ("submitblock", vec![json!(1)], "must be a string"),
        ("getmempoolentry", vec![json!(0)], "must be a string"),
        ("stop", vec![json!("1")], "must be an integer"),
        ("gettxout", vec![json!(1), json!(0)], "must be a string"),
        (
            "prioritisetransaction",
            vec![json!(1), json!(0), json!(1)],
            "must be a string",
        ),
        (
            "testmempoolaccept",
            vec![json!("00")],
            "rawtxs array required",
        ),
        ("submitpackage", vec![json!("00")], "package array required"),
        (
            "gettxspendingprevout",
            vec![json!("00")],
            "outputs array required",
        ),
        ("waitforblock", vec![json!(1)], "must be a string"),
        ("waitforblockheight", vec![json!("1")], "must be an integer"),
        ("waitfornewblock", vec![json!("1")], "must be an integer"),
        ("getnetworkhashps", vec![json!("120")], "must be an integer"),
        ("getrawmempool", vec![json!("true")], "must be a bool"),
    ] {
        let err = dispatch(&ctx, method, params).unwrap_err();
        assert!(
            err["message"].as_str().unwrap_or("").contains(needle),
            "{method}: expected {needle:?} in {err}"
        );
    }

    let wit = dispatch(
        &ctx,
        "decoderawtransaction",
        named(json!({"hexstring": "00", "iswitness": "yes"})),
    )
    .unwrap_err();
    assert!(wit["message"].as_str().unwrap().contains("must be a bool"));

    let extra = dispatch(
        &ctx,
        "decoderawtransaction",
        named(json!({"hexstring": "00", "nope": true})),
    )
    .unwrap_err();
    assert_eq!(extra["code"], ERR_INVALID_PARAMETER);

    let missing = dispatch(&ctx, "validateaddress", vec![]).unwrap_err();
    assert_eq!(missing["code"], ERR_INVALID_PARAMS);
    assert!(missing["message"]
        .as_str()
        .unwrap()
        .contains("address required"));
    let _ = std::fs::remove_dir_all(&dir);

    let (ctx, dir, _hub) = ctx_regtest_hub();
    for (method, params, needle) in [
        ("submitheader", vec![json!(true)], "must be a string"),
        ("invalidateblock", vec![json!(1)], "must be a string"),
        ("reconsiderblock", vec![json!(false)], "must be a string"),
        ("preciousblock", vec![json!(0)], "must be a string"),
        ("setmocktime", vec![json!("0")], "must be an integer"),
        ("mockscheduler", vec![json!("1")], "must be an integer"),
    ] {
        let err = dispatch(&ctx, method, params).unwrap_err();
        assert!(
            err["message"].as_str().unwrap_or("").contains(needle),
            "{method}: expected {needle:?} in {err}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sendraw_testmempoolaccept_submitpackage_junk_hex_is_tx_decode_failed() {
    let (ctx, dir) = ctx_empty();
    for (method, params) in [
        ("sendrawtransaction", vec![json!("ff00baar")]),
        ("testmempoolaccept", vec![json!(["ff00baar"])]),
        ("submitpackage", vec![json!(["ff00baar"])]),
        ("sendrawtransaction", vec![json!("00")]),
    ] {
        let e = dispatch(&ctx, method, params).unwrap_err();
        assert_eq!(e["code"], ERR_DESERIALIZATION, "{method}: {e}");
        assert_eq!(e["message"], json!("TX decode failed:"), "{method}: {e}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rest_chaininfo_and_blockhash_match_rpc() {
    let (ctx, dir) = ctx_empty();
    let info = dispatch_rest(&ctx, "/rest/chaininfo.json", "", &[]);
    assert_eq!(info.status, axum::http::StatusCode::OK);
    let body = String::from_utf8(info.body).unwrap();
    assert!(body.contains("\"chain\":\"regtest\""), "{body}");
    let by_h = dispatch_rest(&ctx, "/rest/blockhashbyheight/0.json", "", &[]);
    assert_eq!(by_h.status, axum::http::StatusCode::NOT_FOUND);
    let off = dispatch_rest(
        &ctx,
        "/rest/blockfilter/basic/0000000000000000000000000000000000000000000000000000000000000000.json",
        "",
        &[],
    );
    assert_eq!(off.status, axum::http::StatusCode::BAD_REQUEST);
    let msg = String::from_utf8(off.body).unwrap();
    assert!(msg.contains("Index is not enabled"), "{msg}");
    let empty = dispatch_rest(&ctx, "/rest/getutxos.json", "", &[]);
    assert_eq!(empty.status, axum::http::StatusCode::BAD_REQUEST);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn http_wait_satisfied_tracks_the_setter() {
    set_http_wait_satisfied(false);
    assert!(
        !http_wait_satisfied(),
        "the blocking dispatch has not been told the HTTP task already waited"
    );
    set_http_wait_satisfied(true);
    assert!(http_wait_satisfied());
    set_http_wait_satisfied(false);
    assert!(!http_wait_satisfied());
}

/// Core never sets `BLOCK_FAILED_VALID` on a system error: a store read
/// fault during `submitblock` must leave the block submittable again.
/// `BIP22ValidationResult` throws `RPC_VERIFY_ERROR` for `state.IsError()`
/// instead of returning a reject-reason string.
#[test]
fn submitblock_store_fault_does_not_cache_block_invalid() {
    let (ctx, dir, hub) = ctx_regtest_hub();
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    let mine_on = |prev: BlockHash, height: u32, time: u32| {
        rbitcoin_consensus::mine_regtest_paying(prev, time, height, op_true.clone(), vec![])
    };
    let t0 = hub.tip_header().unwrap().time;
    let b1 = mine_on(hub.tip_hash().unwrap(), 1, t0 + 1);
    let b2 = mine_on(b1.block_hash(), 2, t0 + 2);
    for b in [&b1, &b2] {
        let r = dispatch(&ctx, "submitblock", vec![json!(block_hex(b))]).unwrap();
        assert!(r.is_null(), "{r}");
    }
    let s2 = mine_on(b1.block_hash(), 2, t0 + 3);
    let r = dispatch(&ctx, "submitblock", vec![json!(block_hex(&s2))]).unwrap();
    assert_eq!(r, "inconclusive", "equal-work sibling is held");

    let body = walk_for(&dir.join("store"), "txout.body").expect("txout.body");
    std::fs::OpenOptions::new()
        .write(true)
        .open(body)
        .unwrap()
        .set_len(0)
        .unwrap();

    let s3 = mine_on(s2.block_hash(), 3, t0 + 4);
    for attempt in 0..2 {
        let e = dispatch(&ctx, "submitblock", vec![json!(block_hex(&s3))])
            .expect_err("a local store fault is an RPC error, not a BIP22 result");
        assert_eq!(e["code"], ERR_VERIFY_ERROR, "attempt {attempt}: {e}");
        assert!(
            e["message"]
                .as_str()
                .unwrap_or_default()
                .starts_with("store: "),
            "attempt {attempt}: the reorg disconnect read must fault: {e}"
        );
        assert!(
            !hub.is_block_invalid(&s3.block_hash()),
            "attempt {attempt}: a store fault is not a block verdict"
        );
        assert_eq!(hub.tip_hash(), Some(b2.block_hash()));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A store fault reading the parent header is not `prev-blk-not-found`.
#[test]
fn submitblock_prev_header_read_fault_is_rpc_error() {
    let (ctx, dir, hub) = ctx_regtest_hub();
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    let mine_on = |prev: BlockHash, height: u32, time: u32| {
        rbitcoin_consensus::mine_regtest_paying(prev, time, height, op_true.clone(), vec![])
    };
    let t0 = hub.tip_header().unwrap().time;
    let b1 = mine_on(hub.tip_hash().unwrap(), 1, t0 + 1);
    let b2 = mine_on(b1.block_hash(), 2, t0 + 2);
    for b in [&b1, &b2] {
        let r = dispatch(&ctx, "submitblock", vec![json!(block_hex(b))]).unwrap();
        assert!(r.is_null(), "{r}");
    }
    let s2 = mine_on(b1.block_hash(), 2, t0 + 3);
    let body = walk_for(&dir.join("store"), "header.body").expect("header.body");
    std::fs::OpenOptions::new()
        .write(true)
        .open(body)
        .unwrap()
        .set_len(0)
        .unwrap();

    let e = dispatch(&ctx, "submitblock", vec![json!(block_hex(&s2))])
        .expect_err("a parent header read fault is an RPC error");
    assert_eq!(e["code"], ERR_VERIFY_ERROR, "{e}");
    assert!(
        e["message"]
            .as_str()
            .unwrap_or_default()
            .starts_with("store: "),
        "{e}"
    );
    assert!(!hub.is_block_invalid(&s2.block_hash()));
    let _ = std::fs::remove_dir_all(&dir);
}

include!("regtest_chain_ops_journey.rs");
