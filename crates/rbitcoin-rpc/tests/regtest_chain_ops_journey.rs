/// Next OP_TRUE coinbase height the journey has not spent yet.
struct TrueCoinbases(u32);

impl TrueCoinbases {
    fn take(&mut self) -> u32 {
        self.0 += 1;
        self.0 - 1
    }
}

fn tip_count(ctx: &RpcContext) -> u64 {
    dispatch(ctx, "getblockcount", vec![]).unwrap().as_u64().unwrap()
}

fn best_hash(ctx: &RpcContext) -> Value {
    dispatch(ctx, "getbestblockhash", vec![]).unwrap()
}

fn block_hex(block: &Block) -> String {
    rbitcoin_primitives::hex_encode(bitcoin::consensus::encode::serialize(block))
}

fn tx_hex(tx: &Transaction) -> String {
    rbitcoin_primitives::hex_encode(bitcoin::consensus::encode::serialize(tx))
}

fn propose(ctx: &RpcContext, block: &Block) -> Value {
    let req = json!({"mode": "proposal", "data": block_hex(block), "rules": ["segwit"]});
    dispatch(ctx, "getblocktemplate", vec![req]).unwrap()
}

/// Child of the tip carrying the tip's coinbase re-stamped with the child's
/// BIP34 height, for proposal needles.
fn proposal_on_tip(ctx: &RpcContext, extra: Vec<Transaction>) -> Block {
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::TxMerkleNode;
    let raw = dispatch(ctx, "getblock", vec![best_hash(ctx), json!(0)]).unwrap();
    let mined: Block = deserialize(&rbitcoin_primitives::hex_decode(raw.as_str().unwrap()).unwrap()).unwrap();
    let mut coinbase = mined.txdata[0].clone();
    let mut height_push = rbitcoin_consensus::bip34_height_script(tip_count(ctx) as u32 + 1);
    height_push.resize(height_push.len().max(2), 0x00);
    coinbase.input[0].script_sig = ScriptBuf::from_bytes(height_push);
    let mut txdata = vec![coinbase];
    txdata.extend(extra);
    let mut next = Block {
        header: Header {
            version: BlockVersion::from_consensus(0x2000_0000),
            prev_blockhash: mined.block_hash(),
            merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
            time: mined.header.time.saturating_add(1),
            bits: mined.header.bits,
            nonce: 0,
        },
        txdata,
    };
    next.header.merkle_root = next.compute_merkle_root().unwrap();
    next
}

fn regrind(block: &mut Block) {
    let target = bitcoin::Target::from_compact(block.header.bits);
    for nonce in 0..u32::MAX {
        block.header.nonce = nonce;
        if block.header.validate_pow(target).is_ok() {
            return;
        }
    }
}

/// One regtest hub from genesis through the first submits: mine, headers,
/// mocktime, and the consensus rejects that do not need a mature coinbase.
#[test]
fn rpc_regtest_from_genesis() {
    let (mut ctx, dir, hub) = ctx_regtest_hub();
    let help = dispatch(&ctx, "help", vec![json!("getnetworkhashps")]).unwrap();
    let h = help.as_str().expect("help is a string");
    assert!(
        h.to_lowercase().contains("chainwork") && !h.contains("Dummy 2-work"),
        "hashrate help must name chainwork, not dummy 2-work: {h}"
    );
    chain_ops_client_param_edges(&mut ctx);
    let (addr, p2wpkh) = p2wpkh_regtest();
    let store = dir.join("store");
    chain_ops_genesis_client_edges(&ctx);
    chain_ops_at_genesis(&ctx, &hub, &store);
    chain_ops_refusals_at_genesis(&ctx, &hub);
    chain_ops_first_block_to_an_address(&ctx, &hub, &addr, &p2wpkh);
    chain_ops_first_block_info(&ctx, &hub, &store, &p2wpkh);
    chain_ops_mocktime(&ctx, &hub, &p2wpkh);
    chain_ops_coinbase_only_blocks(&ctx);
    chain_ops_empty_template_and_proposals(&ctx);
    chain_ops_header_rejects(&ctx, &hub, &p2wpkh);
    chain_ops_submit_rejects(&ctx, &hub, &p2wpkh);
    chain_ops_equal_work_sibling_checkblock(&ctx, &hub);
    chain_ops_coinbase_script_and_sigops(&ctx, &hub, &p2wpkh);
    chain_ops_submit_tx_shape(&ctx, &hub, &p2wpkh);
    chain_ops_echo_overlap(&ctx);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Param, help, stop, and network-identity outcomes on the hub this journey
/// already opened. Knobs this beat flips (stop, network) are put back before
/// the later chain beats. Tip stays at genesis.
fn chain_ops_client_param_edges(ctx: &mut RpcContext) {
    assert_eq!(tip_count(ctx), 0);
    chain_ops_waiters_return_on_stop(ctx);
    chain_ops_stop_sets_flag(ctx);
    chain_ops_help_lists_every_method(ctx);
    chain_ops_named_help(ctx);
    chain_ops_signet_challenge_and_filtertype(ctx);
    chain_ops_unknown_named_param(ctx);
    chain_ops_wrong_json_types(ctx);
    chain_ops_regtest_type_errors(ctx);
    chain_ops_junk_tx_hex(ctx);
    chain_ops_network_identity(ctx);
    ctx.stop.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(ctx.network, Network::Regtest);
    assert_eq!(tip_count(ctx), 0);
}

fn chain_ops_stop_sets_flag(ctx: &RpcContext) {
    assert!(
        !ctx.stop.load(std::sync::atomic::Ordering::SeqCst),
        "later beats still run on this hub"
    );
    let stopped = dispatch(ctx, "stop", vec![]).unwrap();
    assert_eq!(stopped, json!("rbitcoin stopping"));
    assert!(ctx.stop.load(std::sync::atomic::Ordering::SeqCst));
    ctx.stop.store(false, std::sync::atomic::Ordering::SeqCst);
}

fn chain_ops_waiters_return_on_stop(ctx: &RpcContext) {
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::{Duration, Instant};

    let wake = |stop: std::sync::Arc<std::sync::atomic::AtomicBool>| {
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            stop.store(true, Ordering::SeqCst);
        })
    };
    let stop = std::sync::Arc::clone(&ctx.stop);
    let h = wake(stop);
    let t0 = Instant::now();
    let got = dispatch(ctx, "waitfornewblock", vec![json!(5_000)]).unwrap();
    assert_eq!(got["height"], 0);
    assert!(
        t0.elapsed() < Duration::from_millis(1_000),
        "stop must wake the waiter, not the timeout"
    );
    h.join().unwrap();

    ctx.stop.store(false, Ordering::SeqCst);
    let stop = std::sync::Arc::clone(&ctx.stop);
    let h = wake(stop);
    let t0 = Instant::now();
    let missing = "00".repeat(32);
    let got = dispatch(ctx, "waitforblock", vec![json!(missing), json!(5_000)]).unwrap();
    assert_eq!(got["height"], 0);
    assert!(t0.elapsed() < Duration::from_millis(1_000));
    h.join().unwrap();

    ctx.stop.store(false, Ordering::SeqCst);
    let stop = std::sync::Arc::clone(&ctx.stop);
    let h = wake(stop);
    let t0 = Instant::now();
    let got = dispatch(ctx, "waitforblockheight", vec![json!(99), json!(5_000)]).unwrap();
    assert_eq!(got["height"], 0);
    assert!(t0.elapsed() < Duration::from_millis(1_000));
    h.join().unwrap();
    ctx.stop.store(false, Ordering::SeqCst);
}

fn chain_ops_help_lists_every_method(ctx: &RpcContext) {
    let help = dispatch(ctx, "help", vec![]).expect("help");
    let help_text = help.as_str().expect("help string");
    let info = dispatch(ctx, "getrpcinfo", vec![]).expect("getrpcinfo");
    let listed = info["methods"]
        .as_array()
        .expect("methods array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();
    for name in ["generate", "mockscheduler", "addpeeraddress", "getnodeaddresses"] {
        assert!(
            help_text.lines().any(|l| l == name),
            "help missing {name}: {help_text}"
        );
        assert!(
            listed.contains(&name),
            "getrpcinfo.methods missing {name}: {listed:?}"
        );
        let err = dispatch(ctx, name, vec![]).err();
        if let Some(e) = err {
            assert_ne!(
                e["message"].as_str(),
                Some("Method not found"),
                "{name} dispatched as missing"
            );
        }
    }
    for name in listed {
        let err = dispatch(ctx, name, vec![]).err();
        if let Some(e) = err {
            assert_ne!(
                e["message"].as_str(),
                Some("Method not found"),
                "{name} in the catalog but dispatch misses it"
            );
        }
    }
    // `stop` is in the catalog and sets the flag. Later beats must not see it.
    ctx.stop.store(false, std::sync::atomic::Ordering::SeqCst);
}

fn chain_ops_named_help(ctx: &RpcContext) {
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
        let h = dispatch(ctx, "help", vec![json!(m)]).unwrap();
        let h = h.as_str().unwrap();
        assert!(
            h.starts_with(m),
            "help for listed method {m} must start with the name: {h}"
        );
        assert!(
            !h.starts_with("unknown method"),
            "listed method {m} must not be unknown: {h}"
        );
    }
    let unknown = dispatch(ctx, "help", vec![json!("not-a-method")]).unwrap();
    assert_eq!(unknown.as_str().unwrap(), "unknown method not-a-method");
}

fn chain_ops_signet_challenge_and_filtertype(ctx: &mut RpcContext) {
    let info = dispatch(ctx, "getblockchaininfo", vec![]).unwrap();
    assert!(info.get("signet_challenge").is_none());
    let mining = dispatch(ctx, "getmininginfo", vec![]).unwrap();
    assert!(mining.get("signet_challenge").is_none());

    let prev = ctx.network;
    ctx.network = Network::Signet;
    let expect = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";
    let info = dispatch(ctx, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(info["chain"], "signet");
    assert_eq!(info["signet_challenge"], json!(expect));
    let mining = dispatch(ctx, "getmininginfo", vec![]).unwrap();
    assert_eq!(mining["signet_challenge"], json!(expect));
    assert_eq!(mining["blocks"], 0);
    assert!(mining.get("currentblocktx").is_none());
    assert!(mining.get("currentblockweight").is_none());
    ctx.network = prev;

    let err = dispatch(
        ctx,
        "getblockfilter",
        vec![json!("00".repeat(32)), json!("unknown")],
    )
    .unwrap_err();
    assert_eq!(err["code"], ERR_INVALID_ADDRESS_OR_KEY);
    assert!(err["message"]
        .as_str()
        .unwrap()
        .contains("Unknown filtertype"));
}

fn chain_ops_unknown_named_param(ctx: &RpcContext) {
    let info = dispatch(ctx, "getrpcinfo", vec![]).unwrap();
    let listed = info["methods"].as_array().unwrap();
    assert!(listed.len() >= 50, "catalog shrank: {}", listed.len());
    for name in listed.iter().filter_map(|v| v.as_str()) {
        let err = dispatch(ctx, name, named(json!({"not_a_real_rpc_param": 1}))).unwrap_err();
        assert_eq!(err["code"], ERR_INVALID_PARAMETER, "{name}: {err}");
        assert!(
            err["message"]
                .as_str()
                .unwrap()
                .contains("Unknown named parameter not_a_real_rpc_param"),
            "{name}: {err}"
        );
    }
}

fn chain_ops_wrong_json_types(ctx: &RpcContext) {
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
        let err = dispatch(ctx, method, params).unwrap_err();
        assert!(
            err["message"].as_str().unwrap_or("").contains(needle),
            "{method}: expected {needle:?} in {err}"
        );
    }
    let wit = dispatch(
        ctx,
        "decoderawtransaction",
        named(json!({"hexstring": "00", "iswitness": "yes"})),
    )
    .unwrap_err();
    assert!(wit["message"].as_str().unwrap().contains("must be a bool"));
    let extra = dispatch(
        ctx,
        "decoderawtransaction",
        named(json!({"hexstring": "00", "nope": true})),
    )
    .unwrap_err();
    assert_eq!(extra["code"], ERR_INVALID_PARAMETER);
    let missing = dispatch(ctx, "validateaddress", vec![]).unwrap_err();
    assert_eq!(missing["code"], ERR_INVALID_PARAMS);
    assert!(missing["message"]
        .as_str()
        .unwrap()
        .contains("address required"));
}

fn chain_ops_regtest_type_errors(ctx: &RpcContext) {
    for (method, params, needle) in [
        ("submitheader", vec![json!(true)], "must be a string"),
        ("invalidateblock", vec![json!(1)], "must be a string"),
        ("reconsiderblock", vec![json!(false)], "must be a string"),
        ("preciousblock", vec![json!(0)], "must be a string"),
        ("setmocktime", vec![json!("0")], "must be an integer"),
        ("mockscheduler", vec![json!("1")], "must be an integer"),
    ] {
        let err = dispatch(ctx, method, params).unwrap_err();
        assert!(
            err["message"].as_str().unwrap_or("").contains(needle),
            "{method}: expected {needle:?} in {err}"
        );
    }
}

fn chain_ops_junk_tx_hex(ctx: &RpcContext) {
    for (method, params) in [
        ("sendrawtransaction", vec![json!("ff00baar")]),
        ("testmempoolaccept", vec![json!(["ff00baar"])]),
        ("submitpackage", vec![json!(["ff00baar"])]),
        ("sendrawtransaction", vec![json!("00")]),
    ] {
        let e = dispatch(ctx, method, params).unwrap_err();
        assert_eq!(e["code"], ERR_DESERIALIZATION, "{method}: {e}");
        assert_eq!(e["message"], json!("TX decode failed:"), "{method}: {e}");
    }
}

fn chain_ops_network_identity(ctx: &RpcContext) {
    // The hub this journey opens uses a 300_000_000 weight budget.
    let mem = dispatch(ctx, "getmempoolinfo", vec![]).unwrap();
    assert_eq!(
        mem["maxmempool"].as_u64(),
        Some(75_000_000),
        "maxmempool is the virtual-size byte cap (weight/4), not the weight budget: {mem}"
    );
    assert_ne!(
        mem["maxmempool"].as_u64(),
        Some(300_000_000),
        "maxmempool must not report the weight budget"
    );
    let net = dispatch(ctx, "getnetworkinfo", vec![]).unwrap();
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
        rbitcoin_primitives::rbitcoin_subversion(env!("CARGO_PKG_VERSION"), &[] as &[&str]).unwrap()
    );
    let flags = rbitcoin_net::local_service_flags(false, None);
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
}

/// A second genesis hub. Tip age, the mining-info template latch, and the
/// header-tip cap are visible here before this chain has assembled a template
/// or left IBD. The long regtest journey has already done both.
#[test]
fn chain_ops_fresh_tip_age_template_and_header_cap() {
    let (ctx, dir, hub) = ctx_regtest_hub();
    let gen_time = hub.tip_header().unwrap().time;
    // 10_000s is inside a day and outside either `+` rewrite of `24 * 60 * 60`.
    dispatch(
        &ctx,
        "setmocktime",
        vec![json!(i64::from(gen_time) + 10_000)],
    )
    .unwrap();
    let info = dispatch(&ctx, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(
        info["initialblockdownload"], false,
        "a tip 10000s old is still inside the 24h IBD window"
    );

    let prev = hub.tip_hash().unwrap();
    for i in 0..129u32 {
        let mut hdr = hub.tip_header().unwrap();
        hdr.version = bitcoin::block::Version::from_consensus(4);
        hdr.prev_blockhash = prev;
        hdr.time = gen_time.saturating_add(2).saturating_add(i);
        hdr.nonce = 0;
        let mut merkle = [0u8; 32];
        merkle[..4].copy_from_slice(&i.to_le_bytes());
        hdr.merkle_root = bitcoin::TxMerkleNode::from_byte_array(merkle);
        rbitcoin_consensus::grind_regtest_pow(&mut hdr);
        let hex = rbitcoin_primitives::hex_encode(bitcoin::consensus::encode::serialize(&hdr));
        dispatch(&ctx, "submitheader", vec![json!(hex)]).unwrap();
    }
    let tips = dispatch(&ctx, "getchaintips", vec![]).unwrap();
    let n = tips
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t["status"] == "headers-only")
        .count();
    assert_eq!(n, 128, "header-only tips stay at the 128 cap");

    let before = dispatch(&ctx, "getmininginfo", vec![]).unwrap();
    assert!(
        before.get("currentblockweight").is_none(),
        "getmininginfo names a template weight only after one is built: {before}"
    );
    let _tmpl = dispatch(&ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    let after = dispatch(&ctx, "getmininginfo", vec![]).unwrap();
    assert_eq!(after["currentblockweight"], 8_000);
    assert_eq!(after["currentblocktx"], 0);
    let _ = std::fs::remove_dir_all(&dir);
}

fn chain_ops_echo_overlap(ctx: &RpcContext) {
    let empty = dispatch(ctx, "echo", vec![]).unwrap();
    assert_eq!(empty, json!([]));
    assert_eq!(dispatch(ctx, "echojson", vec![]).unwrap(), json!([]));
    let named_echo = dispatch(ctx, "echo", named(json!({"arg0": 0, "arg9": 9}))).unwrap();
    let mut want = vec![Value::Null; 10];
    want[0] = json!(0);
    want[9] = json!(9);
    assert_eq!(named_echo, Value::Array(want));
    let arg1 = dispatch(ctx, "echo", named(json!({"arg1": 1}))).unwrap();
    assert_eq!(arg1, json!([Value::Null, 1]));
    let arg9_null = dispatch(ctx, "echo", named(json!({"arg9": null}))).unwrap();
    assert_eq!(arg9_null, json!(vec![Value::Null; 10]));
    let mixed = dispatch(
        ctx,
        "echo",
        named(json!({"args": [0, 1], "arg3": 3, "arg5": 5})),
    )
    .unwrap();
    assert_eq!(mixed, json!([0, 1, Value::Null, 3, Value::Null, 5]));
    let twice_null = dispatch(
        ctx,
        "echo",
        named(json!({"args": [0, null, 2], "arg1": 1})),
    )
    .unwrap_err();
    assert_eq!(twice_null["code"], ERR_INVALID_PARAMETER);
    let gh = dispatch(ctx, "getblockhash", named(json!({"args": [0]}))).unwrap_err();
    assert_eq!(gh["code"], ERR_INVALID_PARAMETER);
    assert_eq!(gh["message"], "Unknown named parameter args");

    let twice = dispatch(ctx, "echo", named(json!({"args": [0, 1], "arg1": 1}))).unwrap_err();
    assert_eq!(twice["code"], ERR_INVALID_PARAMETER);
    assert_eq!(
        twice["message"],
        "Parameter arg1 specified twice both as positional and named argument"
    );

    let mined = dispatch(
        ctx,
        "generatetodescriptor",
        vec![
            json!(1),
            json!("raw(76a9146cc878e0a0a1a28f80faef74746599f880e770a088ac)"),
        ],
    )
    .unwrap();
    assert_eq!(mined.as_array().unwrap().len(), 1, "{mined}");
}

/// One regtest hub past maturity: templates, sigops, packages, invalidate,
/// and a mainnet view of that same hub. The genesis rejects are a separate
/// chain; this one mines its own pad inside 121..144.
#[test]
fn rpc_regtest_mature_chain_ops() {
    let (mut ctx, dir, hub) = ctx_regtest_hub();
    let (addr, p2wpkh) = p2wpkh_regtest();
    let store = dir.join("store");
    let mut cbs = TrueCoinbases(tip_count(&ctx) as u32 + 1);
    dispatch(&ctx, "generate", vec![json!(130)]).unwrap();
    chain_ops_mature_pad_work(&ctx);
    chain_ops_template_sigops_and_script_reject(&ctx, &mut cbs);
    chain_ops_sigop_adjusted_entry_and_min_fee(&ctx, &mut cbs);
    chain_ops_submitpackage_sigop_vsize(&ctx, &mut cbs);
    chain_ops_big_sigops_cluster(&ctx, &mut cbs);
    chain_ops_prioritise(&ctx, &mut cbs);
    chain_ops_template_orders_rate_then_fee(&ctx, &mut cbs);
    let fee_block = chain_ops_generateblock_and_parent_first(&ctx, &mut cbs);
    chain_ops_proposal_spends(&ctx, &mut cbs);
    chain_ops_submit_repeated_txids(&ctx, &hub, &mut cbs);
    chain_ops_submit_overweight(&ctx, &hub, &mut cbs);
    chain_ops_maxfeerate(&ctx, &mut cbs);
    chain_ops_invalidate_and_precious(&ctx, &hub, &mut cbs, &p2wpkh);
    chain_ops_reconsider_most_work(&ctx, &hub, &p2wpkh);
    chain_ops_held_height_and_work(&ctx, &hub, &p2wpkh);

    // Two networks cannot be one chain: the same hub behind a mainnet RPC view.
    ctx.network = Network::Mainnet;
    for (m, params) in [
        ("generatetoaddress", vec![json!(1), json!(addr.clone())]),
        ("generateblock", vec![json!(addr.clone()), json!([])]),
        ("generate", vec![json!(1)]),
        ("setmocktime", vec![json!(1)]),
    ] {
        let e = dispatch(&ctx, m, params).unwrap_err();
        assert!(
            e["message"].as_str().unwrap_or("").contains("regtest only"),
            "{m} must refuse on mainnet: {e}"
        );
    }
    ctx.regtest = None;
    let before = tip_count(&ctx);
    let good = rbitcoin_consensus::mine_regtest_paying(
        hub.tip_hash().unwrap(),
        hub.tip_header().unwrap().time + 1,
        before as u32 + 1,
        p2wpkh,
        vec![],
    );
    let r = dispatch(&ctx, "submitblock", vec![json!(block_hex(&good))])
        .unwrap_or_else(|e| panic!("submitblock on mainnet must not be regtest-only: {e}"));
    assert!(r.is_null(), "good submitblock on mainnet: {r}");
    assert_eq!(tip_count(&ctx), before + 1);
    chain_ops_corrupt_input_edge(&ctx, &store, fee_block);
    let _ = std::fs::remove_dir_all(&dir);
}

fn chain_ops_genesis_not_an_ordinary_tx(ctx: &RpcContext) {
    let genesis = bitcoin::blockdata::constants::genesis_block(BtcNetwork::Regtest);
    let g_txid = genesis.txdata[0].compute_txid().to_string();
    let g_hash = genesis.block_hash().to_string();
    for params in [
        vec![json!(g_txid.clone())],
        vec![json!(g_txid.clone()), json!(1)],
        vec![json!(g_txid.clone()), json!(2), json!(g_hash)],
    ] {
        let e = dispatch(ctx, "getrawtransaction", params.clone()).unwrap_err();
        assert_eq!(e["code"], ERR_INVALID_ADDRESS_OR_KEY, "{params:?}: {e}");
        assert_eq!(
            e["message"],
            "The genesis block coinbase is not considered an ordinary transaction and cannot be retrieved",
            "{params:?}: {e}"
        );
    }
    for ext in ["json", "hex", "bin"] {
        let rest = dispatch_rest(ctx, &format!("/rest/tx/{g_txid}.{ext}"), "", &[]);
        assert_eq!(rest.status, axum::http::StatusCode::NOT_FOUND, "{ext}");
        let body = String::from_utf8(rest.body).unwrap();
        assert_eq!(body.trim_end(), format!("{g_txid} not found"), "{ext}");
    }

}

fn chain_ops_estimate_fee_edges(ctx: &RpcContext) {
    let missing = dispatch(ctx, "gettxout", vec![json!("00".repeat(32)), json!(0)]).unwrap();
    assert!(missing.is_null(), "unknown outpoint must be JSON null: {missing}");

    let r = dispatch(ctx, "estimatesmartfee", vec![json!(2)]).unwrap();
    assert!(r.get("feerate").is_none(), "no estimate has no feerate: {r}");
    assert_eq!(r["errors"][0], "Insufficient data or no feerate found", "{r}");
    assert_eq!(r["blocks"], 2, "{r}");
    for target in [2_u64, 6, 12, 100] {
        let fee = dispatch(ctx, "estimatesmartfee", vec![json!(target)]).unwrap();
        assert!(
            fee.get("feerate").is_some() || fee.get("errors").is_some(),
            "estimatesmartfee {target}: {fee}"
        );
        if let Some(n) = fee["blocks"].as_u64() {
            assert!(n >= 1, "{fee}");
        }
    }
}

fn chain_ops_estimate_fee_param_gates(ctx: &RpcContext) {
    let e = dispatch(ctx, "estimatesmartfee", vec![]).unwrap_err();
    assert_eq!(e["code"], ERR_MISC);
    assert!(e["message"].as_str().unwrap().contains("estimatesmartfee"), "{e}");
    let e = dispatch(ctx, "estimaterawfee", vec![]).unwrap_err();
    assert_eq!(e["code"], ERR_MISC);
    assert!(e["message"].as_str().unwrap().contains("estimaterawfee"), "{e}");
    let e = dispatch(ctx, "estimatesmartfee", vec![json!("foo")]).unwrap_err();
    assert_eq!(e["code"], ERR_TYPE_ERROR);
    assert!(
        e["message"].as_str().unwrap().contains("JSON value of type string is not of expected type number"),
        "{e}"
    );
    let e = dispatch(ctx, "estimatesmartfee", vec![json!(1), json!(1)]).unwrap_err();
    assert_eq!(e["code"], ERR_TYPE_ERROR);
    assert!(
        e["message"].as_str().unwrap().contains("JSON value of type number is not of expected type string"),
        "{e}"
    );
}

fn chain_ops_estimate_fee_options(ctx: &RpcContext) {
    let e = dispatch(ctx, "estimatesmartfee", vec![json!(1), json!("foo")]).unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert!(e["message"].as_str().unwrap().contains("Invalid estimate_mode parameter"), "{e}");
    let e = dispatch(ctx, "estimatesmartfee", vec![json!(1), json!("ECONOMICAL"), json!(1)]).unwrap_err();
    assert_eq!(e["code"], ERR_TYPE_ERROR);
    assert!(
        e["message"].as_str().unwrap().contains("not of expected type object"),
        "{e}"
    );
    let e = dispatch(
        ctx,
        "estimatesmartfee",
        vec![json!(1), json!("ECONOMICAL"), json!({"fee_rate_estimator": 1})],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_TYPE_ERROR);
    assert_eq!(
        e["message"],
        "JSON value of type number for field fee_rate_estimator is not of expected type string"
    );
    let e = dispatch(
        ctx,
        "estimatesmartfee",
        vec![json!(1), json!("ECONOMICAL"), json!({"verbosity": "foo"})],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_TYPE_ERROR);
    assert_eq!(
        e["message"],
        "JSON value of type string for field verbosity is not of expected type number"
    );
    let e = dispatch(
        ctx,
        "estimatesmartfee",
        vec![json!(1), json!("ECONOMICAL"), json!({"fee_rate_estimator": "foo"})],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert!(
        e["message"].as_str().unwrap().contains("Invalid fee_rate_estimator parameter"),
        "{e}"
    );
    let e = dispatch(
        ctx,
        "estimatesmartfee",
        named(json!({"conf_target": 1, "fee_rate_estimator": true})),
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert_eq!(e["message"], "Unknown named parameter fee_rate_estimator");
    let mixed = RpcParams::from_json(&json!({"args": [1], "fee_rate_estimator": true})).unwrap();
    let e = dispatch(ctx, "estimatesmartfee", mixed).unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert_eq!(e["message"], "Unknown named parameter fee_rate_estimator");
    let e = dispatch(
        ctx,
        "estimatesmartfee",
        vec![json!(1), json!("ECONOMICAL"), json!({"block_policy_only": true})],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_TYPE_ERROR);
    assert_eq!(e["message"], "Unexpected key block_policy_only");
    let e = dispatch(
        ctx,
        "estimatesmartfee",
        vec![json!(1), json!("ECONOMICAL"), json!({}), json!(1)],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_MISC);
    assert!(e["message"].as_str().unwrap().contains("estimatesmartfee"), "{e}");
}

fn chain_ops_estimate_fee_conf_target(ctx: &RpcContext) {
    for method in ["estimatesmartfee", "estimaterawfee"] {
        for bad in [json!(0), json!(1009), json!(-1)] {
            let e = dispatch(ctx, method, vec![bad]).unwrap_err();
            assert_eq!(e["code"], ERR_INVALID_PARAMETER, "{method}");
            assert!(
                e["message"].as_str().unwrap().contains("Invalid conf_target, must be between 1 and 1008"),
                "{method} {e}"
            );
        }
        // Core v31.1 reads conf_target as an int32: 2^32 + 1 does not wrap to 1.
        let float = |token: &str| serde_json::from_str::<Value>(token).unwrap();
        for wide in [
            json!(4_294_967_297_u64),
            json!(2_147_483_648_u64),
            json!(2.5),
            float("6.0"),
            float("1e1"),
        ] {
            let e = dispatch(ctx, method, vec![wide.clone()]).unwrap_err();
            assert_eq!(e["code"], ERR_MISC, "{method} {wide}: {e}");
            assert_eq!(e["message"], "JSON integer out of range", "{method} {wide}");
        }
    }
}

fn chain_ops_estimate_fee_accepted(ctx: &RpcContext) {
    dispatch(ctx, "estimatesmartfee", vec![json!(1)]).unwrap();
    dispatch(ctx, "estimatesmartfee", vec![json!(1), json!("ECONOMICAL")]).unwrap();
    let raw = dispatch(ctx, "estimaterawfee", vec![json!(1)]).unwrap();
    assert!(raw.get("feerate").is_some(), "{raw}");
    assert!(raw.get("short").is_none(), "{raw}");
    dispatch(ctx, "estimaterawfee", vec![json!(1), json!(1)]).unwrap();
    dispatch(ctx, "estimatesmartfee", vec![json!(1), json!("unset")]).unwrap();
    dispatch(ctx, "estimatesmartfee", vec![json!(1), json!("conservative")]).unwrap();
    dispatch(
        ctx,
        "estimatesmartfee",
        vec![json!(1), json!("ECONOMICAL"), json!({"fee_rate_estimator": "block_policy"})],
    )
    .unwrap();
    dispatch(
        ctx,
        "estimatesmartfee",
        vec![json!(1), json!("ECONOMICAL"), json!({"fee_rate_estimator": "mempool_policy"})],
    )
    .unwrap();
    dispatch(
        ctx,
        "estimatesmartfee",
        vec![
            json!(1),
            json!("ECONOMICAL"),
            json!({"verbosity": 1, "fee_rate_estimator": "auto"}),
        ],
    )
    .unwrap();
}

fn chain_ops_mempoolinfo_constants(ctx: &RpcContext) {
    let mem = dispatch(ctx, "getmempoolinfo", vec![]).unwrap();
    assert_eq!(mem["permitbaremultisig"], true, "{mem}");
    assert_eq!(mem["fullrbf"], true);
    assert!(mem["maxdatacarriersize"].is_null());
    assert_eq!(mem["limitclustercount"], 64);
    assert_eq!(mem["limitclustersize"], 101_000);
    assert_eq!(mem["loaded"], true);
    assert_eq!(serde_json::to_string(&mem["mempoolminfee"]).unwrap(), "0.00000100");
    assert_eq!(serde_json::to_string(&mem["minrelaytxfee"]).unwrap(), "0.00000100");
    assert_eq!(serde_json::to_string(&mem["total_fee"]).unwrap(), "0.00000000");
    let mp = ctx.mempool.as_ref().unwrap();
    let prior = mp.min_relay_sat_kvb();
    mp.set_min_relay_sat_kvb(2_500);
    let raised = dispatch(ctx, "getmempoolinfo", vec![]).unwrap();
    assert_eq!(serde_json::to_string(&raised["minrelaytxfee"]).unwrap(), "0.00002500");
    assert_eq!(serde_json::to_string(&raised["incrementalrelayfee"]).unwrap(), "0.00000100");
    assert_eq!(serde_json::to_string(&raised["mempoolminfee"]).unwrap(), "0.00002500");
    mp.set_min_relay_sat_kvb(prior);
}

fn chain_ops_missing_methods(ctx: &RpcContext) {
    let missing_rpc = dispatch(ctx, "no-such-rpc", vec![]).unwrap_err();
    let scan = dispatch(ctx, "scantxoutset", vec![json!("start"), json!(["raw(51)"])]).unwrap_err();
    assert_eq!(scan["code"], missing_rpc["code"]);
    assert_eq!(scan["message"], missing_rpc["message"]);
    assert_eq!(scan["code"], ERR_METHOD_NOT_FOUND);
    let combined = dispatch(ctx, "combinerawtransaction", vec![]).unwrap_err();
    assert_eq!(combined["code"], ERR_METHOD_NOT_FOUND);
    let utxo = dispatch(ctx, "gettxoutsetinfo", vec![]).unwrap_err();
    assert_eq!(utxo["code"], ERR_METHOD_NOT_FOUND);
    assert!(utxo["message"].as_str().unwrap_or("").contains("not supported"), "{utxo}");
    let sync = dispatch(ctx, "syncwithvalidationinterfacequeue", vec![]).unwrap_err();
    assert_eq!(sync["code"], ERR_METHOD_NOT_FOUND);
    assert_eq!(sync["message"], "Method not found");
    let help = dispatch(ctx, "help", vec![]).unwrap();
    assert!(!help.as_str().unwrap().lines().any(|l| {
        l == "syncwithvalidationinterfacequeue" || l == "gettxoutsetinfo"
    }));
    let info = dispatch(ctx, "getrpcinfo", vec![]).unwrap();
    let listed: Vec<&str> = info["methods"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
    assert!(!listed.contains(&"syncwithvalidationinterfacequeue"));
    assert!(!listed.contains(&"gettxoutsetinfo"));
}

fn chain_ops_decode_segwit_coinbase(ctx: &RpcContext) {
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
    let obj = dispatch(ctx, "decoderawtransaction", vec![json!(serialize_hex(&coinbase))]).unwrap();
    let vin = &obj["vin"][0];
    assert_eq!(vin["coinbase"], json!("5100"), "{obj}");
    assert!(vin.get("txid").is_none(), "{obj}");
    assert_eq!(vin["txinwitness"], json!(["00".repeat(32)]), "{obj}");
}

/// Reads and rejects on the genesis hub this journey already opened.
/// Nothing here mines, opens a store, or leaves a knob changed.
fn chain_ops_genesis_client_edges(ctx: &RpcContext) {
    assert_eq!(tip_count(ctx), 0);
    chain_ops_genesis_not_an_ordinary_tx(ctx);
    chain_ops_estimate_fee_edges(ctx);
    chain_ops_estimate_fee_param_gates(ctx);
    chain_ops_estimate_fee_options(ctx);
    chain_ops_estimate_fee_conf_target(ctx);
    chain_ops_estimate_fee_accepted(ctx);
    chain_ops_mempoolinfo_constants(ctx);
    chain_ops_missing_methods(ctx);
    chain_ops_decode_segwit_coinbase(ctx);
}

fn chain_ops_genesis_coinbase_not_a_utxo(ctx: &RpcContext) {
    let genesis = bitcoin::blockdata::constants::genesis_block(BtcNetwork::Regtest);
    let g_hash = dispatch(ctx, "getblockhash", vec![json!(0)]).unwrap();
    let g_blk = dispatch(ctx, "getblock", vec![g_hash, json!(2)]).unwrap();
    let g_txid = g_blk["tx"][0]["txid"].as_str().unwrap().to_string();
    assert_eq!(g_txid, genesis.txdata[0].compute_txid().to_string());
    for include_mempool in [true, false] {
        let out = dispatch(ctx, "gettxout", vec![json!(g_txid), json!(0), json!(include_mempool)]).unwrap();
        assert!(out.is_null(), "include_mempool={include_mempool}: {out}");
    }
    let rest = dispatch_rest(ctx, &format!("/rest/getutxos/{g_txid}-0.json"), "", &[]);
    assert_eq!(rest.status, axum::http::StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(&rest.body).unwrap();
    assert_eq!(body["bitmap"], "0", "{body}");

    let h1 = dispatch(ctx, "getblockhash", vec![json!(1)]).unwrap();
    let h1_blk = dispatch(ctx, "getblock", vec![h1, json!(1)]).unwrap();
    let h1_txid = h1_blk["tx"].as_array().unwrap()[0].clone();
    let live = dispatch(ctx, "gettxout", vec![h1_txid, json!(0)]).unwrap();
    assert_eq!(live["coinbase"], true, "{live}");
    assert!(live["confirmations"].as_u64().unwrap() >= 1, "{live}");
}

fn chain_ops_getblockstats_errors(ctx: &RpcContext, header_only: &Block) {
    let e = dispatch(ctx, "getblockstats", vec![json!(2)]).unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert!(
        e["message"].as_str().unwrap().contains("Target block height 2 after current tip 1"),
        "{e}"
    );
    let e = dispatch(ctx, "getblockstats", vec![json!(-1)]).unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert!(e["message"].as_str().unwrap().contains("Target block height -1 is negative"), "{e}");
    let e = dispatch(ctx, "getblockstats", vec![json!(1), json!(["asdfghjkl"])]).unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert_eq!(e["message"], "Invalid selected statistic 'asdfghjkl'");
    let e = dispatch(
        ctx,
        "getblockstats",
        vec![json!("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_ADDRESS_OR_KEY);
    assert_eq!(e["message"], "Block not found");
    let e = dispatch(ctx, "getblockstats", vec![]).unwrap_err();
    assert_eq!(e["code"], ERR_MISC);
    assert_eq!(e["message"], "getblockstats hash_or_height ( stats )");
    let e = dispatch(ctx, "getblockstats", vec![json!("00"), json!(1), json!(2)]).unwrap_err();
    assert_eq!(e["code"], ERR_MISC);
    assert_eq!(e["message"], "getblockstats hash_or_height ( stats )");
    let e = dispatch(ctx, "getblockstats", vec![json!(header_only.block_hash().to_string())]).unwrap_err();
    assert_eq!(e["code"], ERR_MISC);
    assert_eq!(e["message"], "Block not available (not fully downloaded)");
}

fn chain_ops_at_genesis(ctx: &RpcContext, hub: &rbitcoin_net::ChainHub, store: &std::path::Path) {
    let info = dispatch(ctx, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(info["chain"], "regtest", "{info}");
    let store_bytes = dir_file_bytes(store);
    assert!(store_bytes > 0, "open store has table files");
    assert_eq!(
        info["size_on_disk"].as_u64().unwrap(),
        store_bytes,
        "size_on_disk is a walk of {{datadir}}/store"
    );
    assert_eq!(info["blocks"], 0);
    assert_eq!(info["headers"], 0);
    assert_eq!(info["verificationprogress"], 1.0);
    assert_eq!(
        info["initialblockdownload"], true,
        "regtest genesis is older than 24h"
    );
    let gen = dispatch(ctx, "getblockhash", vec![json!(0)]).unwrap();
    let w0 = dispatch(ctx, "getblockheader", vec![gen]).unwrap()["chainwork"].clone();
    assert_eq!(w0, json!(format!("{:064x}", 2)), "genesis work is 2");

    let info = dispatch(ctx, "getdeploymentinfo", vec![]).unwrap();
    assert_eq!(info["height"], 0);
    let d = &info["deployments"];
    assert_eq!(d["csv"]["type"], "buried");
    assert_eq!(d["csv"]["height"], hub.params.csv_height());
    assert_eq!(d["csv"]["active"], true, "next block 1 ≥ csv@1");
    assert_eq!(d["segwit"]["type"], "buried");
    assert_eq!(d["segwit"]["height"], hub.params.segwit_height());
    assert_eq!(d["segwit"]["active"], true, "regtest segwit height 0");
    assert!(d.get("testdummy").is_none(), "no invented BIP9");
    let mut over = rbitcoin_consensus::ChainParams::regtest();
    over.apply_test_activation_height("csv", 102).unwrap();
    assert_eq!(buried_deployments(&over, 100)["csv"]["height"], 102);
    assert_eq!(buried_deployments(&over, 100)["csv"]["active"], false);
    assert_eq!(buried_deployments(&over, 101)["csv"]["active"], true);

}

fn chain_ops_refusals_at_genesis(ctx: &RpcContext, hub: &rbitcoin_net::ChainHub) {
    let mut named = serde_json::Map::new();
    named.insert("output".into(), json!("raw(55)"));
    named.insert("transactions".into(), json!([]));
    named.insert("submit".into(), json!(false));
    let got = dispatch(ctx, "generateblock", RpcParams::named(named)).unwrap();
    assert!(got["hex"].as_str().is_some() && got["hash"].as_str().is_some());
    assert_eq!(hub.tip_height(), Some(0), "submit=false connects nothing");

    let e = dispatch(ctx, "getblocktemplate", vec![json!({})]).unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert!(e["message"].as_str().unwrap().contains("segwit rule"));

    let e = dispatch(
        ctx,
        "prioritisetransaction",
        vec![json!("11".repeat(32)), json!(1), json!(0)],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert!(e["message"]
        .as_str()
        .unwrap()
        .contains("Priority is no longer supported"));
    let missing = dispatch(ctx, "prioritisetransaction", vec![]).unwrap_err();
    assert_eq!(missing["code"], ERR_MISC);
    assert_eq!(missing["message"], "prioritisetransaction");
    let extra = dispatch(ctx, "getprioritisedtransactions", vec![json!(true)]).unwrap_err();
    assert_eq!(extra["code"], ERR_MISC);

    let e = dispatch(ctx, "setmocktime", vec![json!(-1)]).unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert_eq!(
        e["message"],
        "Mocktime must be in the range [0, 9223372036], not -1."
    );
    let e = dispatch(ctx, "mockscheduler", vec![]).unwrap_err();
    assert!(
        e["message"].as_str().unwrap_or("").contains("delta_seconds"),
        "{e}"
    );
    assert!(dispatch(ctx, "mockscheduler", vec![json!(900)])
        .unwrap()
        .is_null());

    for bad in ["xx".repeat(80), "ff".repeat(78)] {
        let e = dispatch(ctx, "submitheader", vec![json!(bad)]).unwrap_err();
        assert_eq!(e["code"], ERR_DESERIALIZATION);
        assert!(
            e["message"]
                .as_str()
                .unwrap()
                .contains("Block header decode failed"),
            "{e}"
        );
    }
    let orphan = bitcoin::consensus::encode::serialize(&bitcoin::block::Header {
        version: bitcoin::block::Version::from_consensus(4),
        prev_blockhash: BlockHash::from_byte_array([0x12; 32]),
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([0; 32]),
        time: 1,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    });
    let e = dispatch(ctx, "submitheader", vec![json!(rbitcoin_primitives::hex_encode(&(orphan)))]).unwrap_err();
    assert_eq!(e["code"], ERR_VERIFY_ERROR);
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .contains("Must submit previous header"),
        "{e}"
    );
    for m in ["invalidateblock", "preciousblock"] {
        let miss = dispatch(ctx, m, vec![json!("00".repeat(32))]).unwrap_err();
        assert_eq!(miss["code"], ERR_INVALID_ADDRESS_OR_KEY, "{m}");
        assert_eq!(miss["message"], "Block not found", "{m}");
    }
    assert_eq!(tip_count(ctx), 0, "not-found invalidate/precious move nothing");
}

fn chain_ops_first_block_to_an_address(
    ctx: &RpcContext,
    hub: &rbitcoin_net::ChainHub,
    addr: &str,
    p2wpkh: &ScriptBuf,
) {
    let hashes = dispatch(ctx, "generatetoaddress", vec![json!(1), json!(addr)]).unwrap();
    let arr = hashes.as_array().expect("hash array");
    assert_eq!(arr.len(), 1);
    assert_eq!(tip_count(ctx), 1);
    let best = best_hash(ctx);
    assert_eq!(best, arr[0]);
    let best_s = best.as_str().unwrap().to_string();
    let tip = hub.tip_hash().unwrap();
    assert_eq!(best_s, tip.to_string(), "getbestblockhash is display order");
    assert_ne!(
        best_s,
        rbitcoin_primitives::hex_encode(tip.to_byte_array()),
        "display order differs from internal hex"
    );
    assert_eq!(dispatch(ctx, "getblockhash", vec![json!(1)]).unwrap(), best);

    let blk = dispatch(ctx, "getblock", vec![best.clone(), json!(2)]).unwrap();
    let cb_out = &blk["tx"][0]["vout"][0]["scriptPubKey"];
    assert_eq!(cb_out["hex"], rbitcoin_primitives::hex_encode(p2wpkh.as_bytes()));
    assert_eq!(cb_out["address"], json!(addr));
    // Core getblock(hash, False) is verbosity 0 (raw hex).
    let raw = dispatch(ctx, "getblock", vec![best.clone(), json!(false)]).unwrap();
    let raw_s = raw.as_str().unwrap();
    assert!(raw_s.len() > 160 && raw_s.len() % 2 == 0, "{raw_s}");
    let hdr = dispatch(ctx, "getblockheader", vec![best.clone()]).unwrap();
    assert_eq!(hdr["height"], 1);
    assert_eq!(hdr["hash"], best);
    let mr = hdr["merkleroot"].as_str().unwrap();
    assert_eq!(mr, hash_hex_display(&parse_hash32_display(mr).unwrap()));
    let hdr_hex = dispatch(ctx, "getblockheader", vec![best.clone(), json!(false)]).unwrap();
    assert_eq!(hdr_hex.as_str().unwrap().len(), 160);
    assert!(dispatch(ctx, "getdifficulty", vec![]).unwrap().is_number());

    let cb_txid = blk["tx"][0]["txid"].as_str().unwrap();
    let raw_tx = dispatch(ctx, "getrawtransaction", vec![json!(cb_txid), json!(0)]).unwrap();
    // Third arg is the block that contains this coinbase.
    let same = dispatch(
        ctx,
        "getrawtransaction",
        vec![json!(cb_txid), json!(0), best.clone()],
    )
    .unwrap();
    assert_eq!(same, raw_tx);
    let verbose = dispatch(ctx, "getrawtransaction", vec![json!(cb_txid), json!(true)]).unwrap();
    assert_eq!(verbose["txid"], cb_txid);
    let internal = rbitcoin_primitives::hex_encode(parse_hash32_display(cb_txid).unwrap());
    assert!(
        dispatch(ctx, "getrawtransaction", vec![json!(internal)]).is_err(),
        "internal-order hex must not resolve as a Core display txid"
    );
    let tma = dispatch(ctx, "testmempoolaccept", vec![json!([raw_tx.clone()])]).unwrap();
    assert_eq!(tma[0]["allowed"], false, "{tma}");
    assert!(dispatch(ctx, "sendrawtransaction", vec![raw_tx]).is_err());
    let net = dispatch(ctx, "getnetworkinfo", vec![]).unwrap();
    assert_eq!(net["connections_in"], 0);
    chain_ops_genesis_coinbase_not_a_utxo(ctx);
}

fn chain_ops_first_block_info(
    ctx: &RpcContext,
    hub: &rbitcoin_net::ChainHub,
    store: &std::path::Path,
    p2wpkh: &ScriptBuf,
) {
    let best = best_hash(ctx);
    let tip = hub.tip_hash().unwrap();
    let info = dispatch(ctx, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(info["blocks"], 1);
    assert_eq!(info["headers"], 1);
    assert_eq!(info["bestblockhash"], best);
    assert!(info["time"].as_u64().unwrap() > 0);
    assert!(info["mediantime"].as_u64().is_some());
    assert_eq!(
        info["size_on_disk"].as_u64().unwrap(),
        dir_file_bytes(store)
    );
    // `feature_maxtipage`: Core computes IsInitialBlockDownload on the call.
    // A stale node-loop copy must not win or resurrect a dummy 0.5 progress.
    ctx.initial_block_download.store(true, Ordering::Relaxed);
    let info = dispatch(ctx, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(info["verificationprogress"], 1.0);
    assert_eq!(
        info["initialblockdownload"], false,
        "fresh generated tip has left IBD; stale RPC atomic must not win"
    );
    ctx.initial_block_download.store(false, Ordering::Relaxed);

    let info = dispatch(ctx, "getdeploymentinfo", vec![]).unwrap();
    assert_eq!(info["height"], 1);
    let d = &info["deployments"];
    for (fork, active) in [("csv", true), ("bip65", true), ("bip66", true), ("bip34", true)] {
        assert_eq!(d[fork]["active"], active, "{fork}");
    }

    let child = rbitcoin_consensus::mine_regtest_paying(
        tip,
        hub.tip_header().unwrap().time + 1,
        2,
        p2wpkh.clone(),
        vec![],
    );
    let r = dispatch(ctx, "submitheader", vec![json!(block_hex(&child))]).unwrap();
    assert!(r.is_null(), "{r}");
    let info = dispatch(ctx, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(info["blocks"], 1);
    assert_eq!(info["headers"], 2);
    assert_eq!(
        info["verificationprogress"], 0.5,
        "headers ahead of bodies: progress is tip/headers"
    );
    let tips = dispatch(ctx, "getchaintips", vec![]).unwrap();
    assert!(
        tips.as_array()
            .unwrap()
            .iter()
            .any(|t| t["status"] == "headers-only" && t["height"] == 2),
        "{tips}"
    );
    chain_ops_getblockstats_errors(ctx, &child);
}

fn chain_ops_mocktime(ctx: &RpcContext, hub: &rbitcoin_net::ChainHub, p2wpkh: &ScriptBuf) {
    let mock = u64::from(hub.tip_header().unwrap().time) + 1_000;
    dispatch(ctx, "setmocktime", vec![json!(mock)]).unwrap();
    let hashes = dispatch(ctx, "generate", vec![json!(1)]).unwrap();
    let hdr = dispatch(ctx, "getblockheader", vec![hashes[0].clone()]).unwrap();
    let t = hdr["time"].as_u64().unwrap();
    assert!(
        (mock..mock + 600).contains(&t),
        "generate time {t} should honor mock {mock}"
    );
    let parent = hub.tip_hash().unwrap();
    let far = rbitcoin_consensus::mine_regtest_paying(
        parent,
        (mock + 3 * 3600) as u32,
        3,
        p2wpkh.clone(),
        vec![],
    );
    let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&far))]).unwrap();
    assert_eq!(r, "time-too-new", "future header vs mock now");
    dispatch(ctx, "setmocktime", vec![json!(mock + 3 * 3600)]).unwrap();
    let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&far))]).unwrap();
    assert!(r.is_null(), "same block once the clock catches up: {r}");
    assert_eq!(best_hash(ctx), json!(far.block_hash().to_string()));

    let sibling = rbitcoin_consensus::mine_regtest_paying(
        parent,
        (mock + 6 * 3600) as u32,
        3,
        p2wpkh.clone(),
        vec![],
    );
    for attempt in ["first", "second"] {
        let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&sibling))]).unwrap();
        assert_eq!(r, "time-too-new", "{attempt} submit of a future fork block");
    }
    assert_eq!(best_hash(ctx), json!(far.block_hash().to_string()));
    // The sibling is still hours ahead of the wall clock. `setmocktime` is
    // the node clock the next submit must use.
    dispatch(ctx, "setmocktime", vec![json!(mock + 6 * 3600)]).unwrap();
    let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&sibling))]).unwrap();
    assert_eq!(
        r, "inconclusive",
        "equal-work fork once the node clock reaches its time: {r}"
    );
    assert_eq!(best_hash(ctx), json!(far.block_hash().to_string()));
    let child = rbitcoin_consensus::mine_regtest_paying(
        sibling.block_hash(),
        (mock + 6 * 3600 + 1) as u32,
        4,
        p2wpkh.clone(),
        vec![],
    );
    let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&child))]).unwrap();
    assert!(
        r.is_null(),
        "heavier fork connects once the node clock allows its parent: {r}"
    );
    assert_eq!(best_hash(ctx), json!(child.block_hash().to_string()));

    // The node clock is still the mock that accepted `child`, so this header's
    // time is legal. Wrong nBits on the non-tip parent is bad-diffbits, and
    // that verdict is remembered. Proof-of-work meets the stated target.
    let mut bad_bits = rbitcoin_consensus::mine_regtest_paying(
        sibling.block_hash(),
        child.header.time,
        4,
        p2wpkh.clone(),
        vec![],
    );
    bad_bits.header.bits = bitcoin::CompactTarget::from_consensus(0x207f_fffe);
    regrind(&mut bad_bits);
    let first = dispatch(ctx, "submitblock", vec![json!(block_hex(&bad_bits))]).unwrap();
    assert_eq!(first, "bad-diffbits", "side block with the wrong bits");
    let second = dispatch(ctx, "submitblock", vec![json!(block_hex(&bad_bits))]).unwrap();
    assert_eq!(second, "duplicate-invalid", "bad-diffbits is remembered");
    assert_eq!(best_hash(ctx), json!(child.block_hash().to_string()));

    dispatch(ctx, "setmocktime", vec![json!(0)]).unwrap();

    // Parent is on the best chain and is not the tip, so this is a side
    // header. Both submits must say time-too-old: that block can never become
    // valid, and Core still answers time-too-old the second time.
    let too_old = rbitcoin_consensus::mine_regtest_paying(
        sibling.block_hash(),
        1,
        4,
        p2wpkh.clone(),
        vec![],
    );
    for attempt in ["first", "second"] {
        let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&too_old))]).unwrap();
        assert_eq!(r, "time-too-old", "{attempt} submit of a too-old side block");
    }
    assert_eq!(best_hash(ctx), json!(child.block_hash().to_string()));
}

fn chain_ops_coinbase_only_blocks(ctx: &RpcContext) {
    let hashes = dispatch(ctx, "generate", vec![json!(2)]).unwrap();
    let first = hashes[0].clone();
    let tip = hashes[1].clone();

    let v1 = dispatch(ctx, "getblock", vec![first.clone(), json!(1)]).unwrap();

    let txs = v1["tx"].as_array().unwrap();
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0].as_str().unwrap().len(), 64);
    let hdr = dispatch(ctx, "getblockheader", vec![first]).unwrap();
    assert_getblock_core_header_keys(&v1, &hdr);
    assert_eq!(v1["nextblockhash"], tip);
    let v2 = dispatch(ctx, "getblock", vec![tip.clone(), json!(2)]).unwrap();
    assert!(v2["tx"][0]["vin"][0].get("coinbase").is_some());
    assert!(v2["tx"][0]["vin"][0].get("txid").is_none());
    let tip_hdr = dispatch(ctx, "getblockheader", vec![tip]).unwrap();
    assert_getblock_core_header_keys(&v2, &tip_hdr);
    assert!(v2.get("nextblockhash").is_none());

    let tip_h = tip_count(ctx);
    let prev_hdr = dispatch(ctx, "getblockheader", vec![tip_hdr["previousblockhash"].clone()])
        .unwrap();
    let dt = tip_hdr["time"].as_u64().unwrap().abs_diff(prev_hdr["time"].as_u64().unwrap());
    let dw = chainwork_f64(tip_hdr["chainwork"].as_str().unwrap())
        - chainwork_f64(prev_hdr["chainwork"].as_str().unwrap());
    let got = dispatch(ctx, "getnetworkhashps", vec![json!(1), json!(tip_h)])
        .unwrap()
        .as_f64()
        .unwrap();
    let expect = if dt == 0 { 0.0 } else { dw / dt as f64 };
    assert!((got - expect).abs() < 1e-9, "got={got} expect={expect}");

}

fn chain_ops_empty_template_and_proposals(ctx: &RpcContext) {
    let tip_h = tip_count(ctx);
    let tmpl = dispatch(ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    assert_eq!(tmpl["height"], tip_h + 1);
    assert_eq!(tmpl["version"], 0x2000_0000, "testdummy is DEFINED below height 144");
    assert!(tmpl["transactions"].as_array().unwrap().is_empty());
    let info = dispatch(ctx, "getmininginfo", vec![]).unwrap();
    assert_eq!(info["blocks"], tip_h);
    assert_eq!(info["pooledtx"], 0);
    assert_eq!(
        info["blockmintxfee"],
        sat_btc_json(1),
        "blockmintxfee is BTC/kvB"
    );

    let next = proposal_on_tip(ctx, vec![]);
    assert!(propose(ctx, &next).is_null(), "valid proposal");
    let mut bad_cb = next.clone();
    bad_cb.txdata[0].input[0].previous_output.txid = Txid::from_byte_array([1u8; 32]);
    assert_eq!(
        propose(ctx, &bad_cb),
        "bad-txnmrklroot",
        "the header still commits to the coinbase txid"
    );
    bad_cb.header.merkle_root = bad_cb.compute_merkle_root().unwrap();
    assert_eq!(propose(ctx, &bad_cb), "bad-cb-missing");
    let mut empty = next.clone();
    empty.txdata.clear();
    assert_eq!(
        propose(ctx, &empty),
        "bad-txnmrklroot",
        "an empty body the header does not commit to"
    );
    empty.header.merkle_root = empty
        .compute_merkle_root()
        .unwrap_or_else(|| bitcoin::TxMerkleNode::from_byte_array([0; 32]));
    assert_eq!(propose(ctx, &empty), "bad-blk-length");
    let mut bits_bad = next.clone();
    bits_bad.header.bits = bitcoin::CompactTarget::from_consensus(469762303);
    assert_eq!(propose(ctx, &bits_bad), "bad-diffbits");
    let mut v3 = next.clone();
    v3.header.version = bitcoin::block::Version::from_consensus(3);
    assert_eq!(propose(ctx, &v3), "bad-version(0x00000003)", "BIP65 floor");
    let mut far = next.clone();
    far.header.time = u32::MAX;
    assert_eq!(propose(ctx, &far), "time-too-new");
    let mut old = next;
    old.header.time = 0;
    assert_eq!(propose(ctx, &old), "time-too-old");

}

fn chain_ops_header_rejects(ctx: &RpcContext, hub: &rbitcoin_net::ChainHub, p2wpkh: &ScriptBuf) {
    let tip_h = tip_count(ctx);
    let mut old_hdr = hub.tip_header().unwrap();
    old_hdr.prev_blockhash = hub.tip_hash().unwrap();
    old_hdr.time = 1;
    let e = dispatch(
        ctx,
        "submitheader",
        vec![json!(rbitcoin_primitives::hex_encode(bitcoin::consensus::encode::serialize(&old_hdr)))],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_VERIFY_ERROR);
    assert!(
        e["message"].as_str().unwrap().contains("time-too-old"),
        "{e}"
    );

    // An invalid body behind two known headers marks that branch, not a new tip.
    let prev = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time + 1;
    let h = tip_h as u32 + 1;
    let mut parent = rbitcoin_consensus::mine_regtest_paying(prev, time, h, p2wpkh.clone(), vec![]);
    parent.txdata[0].output[0].value = Amount::from_sat(100 * 100_000_000);
    parent.header.merkle_root = parent.compute_merkle_root().unwrap();
    regrind(&mut parent);
    let child = rbitcoin_consensus::mine_regtest_paying(
        parent.block_hash(),
        time + 1,
        h + 1,
        p2wpkh.clone(),
        vec![],
    );
    for header in [&parent.header, &child.header] {
        let hex = rbitcoin_primitives::hex_encode(bitcoin::consensus::encode::serialize(header));
        dispatch(ctx, "submitheader", vec![json!(hex)]).unwrap();
    }
    let n_before = dispatch(ctx, "getchaintips", vec![]).unwrap().as_array().unwrap().len();
    dispatch(ctx, "submitblock", vec![json!(block_hex(&parent))]).unwrap();
    let tips = dispatch(ctx, "getchaintips", vec![]).unwrap();
    let tips = tips.as_array().unwrap();
    assert_eq!(tips.len(), n_before, "the rejected parent adds no tip: {tips:?}");
    assert!(tips.iter().any(|t| t["status"] == "invalid"), "{tips:?}");
    assert_eq!(tip_count(ctx), tip_h);
}

fn chain_ops_submit_rejects(ctx: &RpcContext, hub: &rbitcoin_net::ChainHub, p2wpkh: &ScriptBuf) {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, TxIn, TxOut, Witness};
    let mine = |time_off: u32| {
        let h = tip_count(ctx) as u32 + 1;
        let time = hub.tip_header().unwrap().time + 1 + time_off;
        rbitcoin_consensus::mine_regtest_paying(
            hub.tip_hash().unwrap(),
            time,
            h,
            p2wpkh.clone(),
            vec![],
        )
    };
    let before = tip_count(ctx);
    let good = mine(0);
    let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&good))]).unwrap();
    assert!(r.is_null(), "good submitblock: {r}");
    assert_eq!(tip_count(ctx), before + 1);
    let prev_cb = good.txdata[0].compute_txid();

    let mut bad = mine(0);
    bad.header.merkle_root = bitcoin::TxMerkleNode::from_byte_array([0xab; 32]);
    regrind(&mut bad);
    let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&bad))]).unwrap();
    assert_eq!(r, "bad-txnmrklroot");

    // Core CheckMerkleRoot runs before every body rule, so each body below
    // is committed to by its header first.
    let commit = |mut block: Block| {
        block.header.merkle_root = block
            .compute_merkle_root()
            .unwrap_or_else(|| bitcoin::TxMerkleNode::from_byte_array([0; 32]));
        regrind(&mut block);
        block
    };
    let mut empty = mine(1);
    empty.txdata.clear();
    let mut no_cb = mine(2);
    no_cb.txdata[0].input[0].previous_output = OutPoint {
        txid: Txid::from_byte_array([0x11; 32]),
        vout: 0,
    };
    let mut uncommitted = mine(3);
    uncommitted.txdata.push(uncommitted.txdata[0].clone());
    let spend = |prev: OutPoint, sat: u64| Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prev,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(sat),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let mut below = mine(4);
    let cb = below.txdata[0].compute_txid();
    // Inside the money range. CheckBlock would report `bad-txns-vout-toolarge`
    // before this same-block coinbase is immature.
    let over_in = Amount::MAX_MONEY.to_sat();
    below.txdata.push(spend(OutPoint { txid: cb, vout: 0 }, over_in));
    let mut miss = mine(5);
    let ghost = OutPoint {
        txid: Txid::from_byte_array([0x22; 32]),
        vout: 0,
    };
    miss.txdata.push(spend(ghost, 1));
    let mut no_vout = mine(6);
    let cb = no_vout.txdata[0].compute_txid();
    let mut burn = spend(OutPoint { txid: cb, vout: 0 }, 0);
    burn.output.clear();
    no_vout.txdata.push(burn);
    let mut young = mine(7);
    let cb = young.txdata[0].compute_txid();
    young.txdata.push(spend(OutPoint { txid: cb, vout: 0 }, 1));
    // CheckTransaction rejects an empty vin before CheckTxInputs compares values.
    let mut no_vin = mine(8);
    no_vin.txdata.push(Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::new(),
        }],
    });
    // A confirmed coinbase is still immature here. CheckTxInputs reports that
    // before the value check, including when the outputs exceed the inputs.
    let mut young_prev = mine(9);
    young_prev
        .txdata
        .push(spend(OutPoint { txid: prev_cb, vout: 0 }, over_in));
    let no_vin = commit(no_vin);
    for (block, want) in [
        (commit(empty), "bad-blk-length"),
        (commit(no_cb), "bad-cb-missing"),
        (uncommitted, "bad-txnmrklroot"),
        (commit(below), "bad-txns-premature-spend-of-coinbase"),
        (commit(miss), "bad-txns-inputs-missingorspent"),
        (commit(no_vout), "bad-txns-vout-empty"),
        (commit(young), "bad-txns-premature-spend-of-coinbase"),
        (no_vin.clone(), "bad-txns-vin-empty"),
        (commit(young_prev), "bad-txns-premature-spend-of-coinbase"),
    ] {
        let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&block))]).unwrap();
        assert_eq!(r, want);
    }
    assert_eq!(
        dispatch(ctx, "submitblock", vec![json!(block_hex(&no_vin))]).unwrap(),
        "duplicate-invalid",
        "a cheap consensus reject is cached"
    );
    assert_eq!(tip_count(ctx), before + 1);

    // A ground block [cb, t1] has txid(cb) || txid(t1) as one 64-byte tx.
    // That tx alone under the real header must not cache the hash.
    let mut inner = mine(6);
    inner.txdata = vec![spend(
        OutPoint {
            txid: Txid::from_byte_array([0x64; 32]),
            vout: 0,
        },
        0,
    )];
    inner.txdata[0].output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51; 4]);
    assert_eq!(inner.txdata[0].base_size(), 64);
    inner.header.merkle_root = inner.compute_merkle_root().unwrap();
    regrind(&mut inner);
    let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&inner))]).unwrap();
    assert_eq!(r, "bad-cb-missing");
    assert!(
        !hub.is_block_invalid(&inner.block_hash()),
        "a 64-byte tx without a coinbase may be an inner merkle node"
    );
    assert_eq!(tip_count(ctx), before + 1);

    // Witness bytes are not in the block hash. A padded copy is mutated.
    let honest = mine(7);
    let mut padded = honest.clone();
    padded.txdata[0].input[0].witness = Witness::from_slice(&[[0u8; 32]]);
    assert_eq!(padded.block_hash(), honest.block_hash());
    let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&padded))]).unwrap();
    assert!(r.is_string(), "a padded witness rejects: {r}");
    assert!(
        !hub.is_block_invalid(&honest.block_hash()),
        "a mutated submit must not cache the block hash"
    );
    let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&honest))]).unwrap();
    assert!(r.is_null(), "the honest body still connects: {r}");
    assert_eq!(tip_count(ctx), before + 2);

    // CheckBlock money range. MAX_MONEY is not `toolarge` (subsidy rejects
    // it later). One satoshi over is.
    const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
    let mut at_max = mine(10);
    at_max.txdata[0].output[0].value = Amount::from_sat(MAX_MONEY);
    let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&commit(at_max)))]).unwrap();
    assert_eq!(r, "bad-cb-amount", "MAX_MONEY is not toolarge: {r}");
    let mut over = mine(11);
    over.txdata[0].output[0].value = Amount::from_sat(MAX_MONEY + 1);
    let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&commit(over)))]).unwrap();
    assert_eq!(r, "bad-txns-vout-toolarge");

    // Coinbase with no outputs is CheckTransaction, not the spend-loop reject.
    let mut no_cb_out = mine(12);
    no_cb_out.txdata[0].output.clear();
    let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&commit(no_cb_out)))]).unwrap();
    assert_eq!(r, "bad-txns-vout-empty");
}

/// An equal-work sibling never connects, so `submitblock` is the CheckBlock
/// that body gets. Layout rejects are cached; a valid sibling is held.
fn chain_ops_equal_work_sibling_checkblock(ctx: &RpcContext, hub: &rbitcoin_net::ChainHub) {
    use bitcoin::{OutPoint, Txid};
    let tip = hub.tip_header().unwrap();
    let parent = tip.prev_blockhash;
    let height = hub.tip_height().unwrap();
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    let mine_on = |time: u32, h: u32| {
        rbitcoin_consensus::mine_regtest_paying(parent, time, h, op_true.clone(), vec![])
    };
    let commit = |mut block: Block| {
        block.header.merkle_root = block
            .compute_merkle_root()
            .unwrap_or_else(|| bitcoin::TxMerkleNode::from_byte_array([0; 32]));
        regrind(&mut block);
        block
    };
    let mut empty = mine_on(tip.time + 10, height);
    empty.txdata.clear();
    let mut no_cb = mine_on(tip.time + 11, height);
    no_cb.txdata[0].input[0].previous_output = OutPoint {
        txid: Txid::from_byte_array([0x11; 32]),
        vout: 0,
    };
    assert_ne!(
        no_cb.txdata[0].base_size(),
        64,
        "this body is a real non-coinbase, not a 64-byte merkle node"
    );
    let other_cb = mine_on(tip.time + 12, height + 1).txdata.remove(0);
    let mut two_cb = mine_on(tip.time + 13, height);
    two_cb.txdata.push(other_cb);
    let valid = mine_on(tip.time + 14, height);
    for (block, want) in [
        (commit(empty), "bad-blk-length"),
        (commit(no_cb), "bad-cb-missing"),
        (commit(two_cb), "bad-cb-multiple"),
    ] {
        let hash = block.block_hash();
        let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&block))]).unwrap();
        assert_eq!(r, want, "{hash}");
        assert!(hub.is_block_invalid(&hash), "{want} is cached on {hash}");
        let again = dispatch(ctx, "submitblock", vec![json!(block_hex(&block))]).unwrap();
        assert_eq!(again, "duplicate-invalid", "{want} resubmit");
    }
    let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&valid))]).unwrap();
    assert_eq!(r, "inconclusive", "a valid equal-work sibling is held");
    assert!(!hub.is_block_invalid(&valid.block_hash()));
    assert_eq!(hub.tip_hash(), Some(tip.block_hash()));
}

/// Coinbase scriptSig length, BIP34 height, and the legacy sigop cap on the
/// live tip. Regtest activates BIP34 at height 1.
fn chain_ops_coinbase_script_and_sigops(
    ctx: &RpcContext,
    hub: &rbitcoin_net::ChainHub,
    spk: &ScriptBuf,
) {
    let mine_claiming = |claimed: u32| {
        rbitcoin_consensus::mine_regtest_paying(
            hub.tip_hash().unwrap(),
            hub.tip_header().unwrap().time + 1,
            claimed,
            spk.clone(),
            vec![],
        )
    };
    let submit = |b: &Block| dispatch(ctx, "submitblock", vec![json!(block_hex(b))]).unwrap();
    let h = tip_count(ctx) as u32 + 1;
    let wrong = mine_claiming(h + 1);
    assert_eq!(submit(&wrong), "bad-cb-height");
    assert_eq!(
        submit(&wrong),
        "duplicate-invalid",
        "bad-cb-height is a consensus reject, not a mutated body"
    );
    for script_sig in [vec![0x52], vec![]] {
        let mut short = mine_claiming(h);
        short.txdata[0].input[0].script_sig = ScriptBuf::from_bytes(script_sig);
        short.header.merkle_root = short.compute_merkle_root().unwrap();
        regrind(&mut short);
        assert_eq!(submit(&short), "bad-cb-length");
    }
    let r = submit(&mine_claiming(h));
    assert!(r.is_null(), "the right height push connects: {r}");

    // CheckTransaction length is 2..=100, after the merkle check and before BIP34.
    let mut wide = mine_claiming(h + 1);
    let mut ss = rbitcoin_consensus::bip34_height_script(h + 1);
    ss.resize(100, 0x00);
    wide.txdata[0].input[0].script_sig = ScriptBuf::from_bytes(ss);
    wide.header.merkle_root = wide.compute_merkle_root().unwrap();
    regrind(&mut wide);
    let r = submit(&wide);
    assert!(r.is_null(), "a 100-byte coinbase scriptSig connects: {r}");
    let mut too_long = mine_claiming(h + 2);
    let mut ss = rbitcoin_consensus::bip34_height_script(h + 2);
    ss.resize(101, 0x00);
    too_long.txdata[0].input[0].script_sig = ScriptBuf::from_bytes(ss);
    too_long.header.merkle_root = too_long.compute_merkle_root().unwrap();
    regrind(&mut too_long);
    assert_eq!(submit(&too_long), "bad-cb-length");

    // The 101-byte script did not connect, so the next height is still h + 2.
    // Legacy sigops cost is 20_000 × 4. The next CHECKSIG is over the cap.
    let mut sig_ok = mine_claiming(h + 2);
    sig_ok.txdata[0].output[0].script_pubkey = ScriptBuf::from_bytes(vec![0xac; 20_000]);
    sig_ok.header.merkle_root = sig_ok.compute_merkle_root().unwrap();
    regrind(&mut sig_ok);
    let r = submit(&sig_ok);
    assert!(r.is_null(), "20_000 legacy sigops connects: {r}");
    let mut sig_bad = mine_claiming(h + 3);
    sig_bad.txdata[0].output[0].script_pubkey = ScriptBuf::from_bytes(vec![0xac; 20_001]);
    sig_bad.header.merkle_root = sig_bad.compute_merkle_root().unwrap();
    regrind(&mut sig_bad);
    assert_eq!(submit(&sig_bad), "bad-blk-sigops");
}

/// Tx-shape and witness-commitment rejects. None of these connect.
fn chain_ops_submit_tx_shape(
    ctx: &RpcContext,
    hub: &rbitcoin_net::ChainHub,
    p2wpkh: &ScriptBuf,
) {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, TxIn, TxOut, Witness};
    let submit = |block: &Block| dispatch(ctx, "submitblock", vec![json!(block_hex(block))]).unwrap();
    let next = |extra: Vec<Transaction>| {
        let h = tip_count(ctx) as u32 + 1;
        let time = hub.tip_header().unwrap().time + 1;
        rbitcoin_consensus::mine_regtest_paying(
            hub.tip_hash().unwrap(),
            time,
            h,
            p2wpkh.clone(),
            extra,
        )
    };
    let tx_in = |prev: OutPoint| TxIn {
        previous_output: prev,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };
    let one_out = |sat: u64| {
        vec![TxOut {
            value: Amount::from_sat(sat),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }]
    };
    let bare = |input: Vec<TxIn>, output: Vec<TxOut>| Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input,
        output,
    };
    let op = OutPoint {
        txid: Txid::from_byte_array([3; 32]),
        vout: 0,
    };
    let before = tip_count(ctx);
    assert_eq!(
        submit(&next(vec![bare(vec![tx_in(op), tx_in(op)], one_out(1))])),
        "bad-txns-inputs-duplicate"
    );
    let mixed = bare(
        vec![
            tx_in(OutPoint {
                txid: Txid::from_byte_array([4; 32]),
                vout: 0,
            }),
            tx_in(OutPoint::null()),
        ],
        one_out(1),
    );
    assert_eq!(submit(&next(vec![mixed])), "bad-txns-prevout-null");

    // Each output is under MAX_MONEY. The sum is not.
    let half = 11_000_000 * 100_000_000;
    let mut sum = next(vec![]);
    sum.txdata[0].output = vec![
        TxOut {
            value: Amount::from_sat(half),
            script_pubkey: p2wpkh.clone(),
        },
        TxOut {
            value: Amount::from_sat(half),
            script_pubkey: p2wpkh.clone(),
        },
    ];
    sum.header.merkle_root = sum.compute_merkle_root().unwrap();
    regrind(&mut sum);
    assert_eq!(submit(&sum), "bad-txns-txouttotal-toolarge");

    let spend = bare(
        vec![tx_in(OutPoint {
            txid: Txid::from_byte_array([9; 32]),
            vout: 0,
        })],
        one_out(1),
    );
    let mut missing = next(vec![spend.clone()]);
    missing.txdata[1].input[0].witness = Witness::from_slice(&[vec![0x01]]);
    assert_eq!(submit(&missing), "missing witness commitment");

    // A 32-byte nonce with a commitment of zeros is not the witness merkle.
    let mut wrong = next(vec![spend]);
    wrong.txdata[1].input[0].witness = Witness::from_slice(&[vec![0x02]]);
    wrong.txdata[0].input[0].witness = Witness::from_slice(&[[0x11u8; 32]]);
    let mut spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    spk.extend([0u8; 32]);
    wrong.txdata[0].output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(spk),
    });
    wrong.header.merkle_root = wrong.compute_merkle_root().unwrap();
    regrind(&mut wrong);
    assert_eq!(submit(&wrong), "witness commitment mismatch");
    assert_eq!(tip_count(ctx), before);
}

/// Past 120 blocks and short of the 144 retarget window.
fn chain_ops_mature_pad_work(ctx: &RpcContext) {
    let h = tip_count(ctx);
    assert!((121..144).contains(&h), "pad height {h}");
    let hashps = |n: u64| {
        dispatch(ctx, "getnetworkhashps", vec![json!(n)])
            .unwrap()
            .as_f64()
            .unwrap()
    };
    let zero = hashps(0);
    assert_eq!(zero, hashps(h), "nblocks<=0 is height%interval+1 capped to height");
    assert_ne!(zero, hashps(120), "nblocks=0 is not a dummy 120-block window");
    let hdr = dispatch(ctx, "getblockheader", vec![best_hash(ctx)]).unwrap();
    assert_eq!(hdr["chainwork"], json!(format!("{:064x}", 2 * (h + 1))));
    let info = dispatch(ctx, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(info["chainwork"], hdr["chainwork"]);
}

fn chain_ops_template_sigops_and_script_reject(ctx: &RpcContext, cbs: &mut TrueCoinbases) {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, TxIn, TxOut, Witness};
    let a = cbs.take();
    let cb_a = generated_coinbase_value(ctx, a);
    // OP_CHECKSIG: Core GBT sigops = 1 * WITNESS_SCALE_FACTOR.
    let checksig = spend_generated_coinbase(ctx, a, cb_a - 1_000, ScriptBuf::from_bytes(vec![0xac])).1;
    let tid = dispatch(ctx, "sendrawtransaction", vec![json!(tx_hex(&checksig))]).unwrap();
    let tmpl = dispatch(ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    let txs = tmpl["transactions"].as_array().unwrap();
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0]["txid"], tid);
    assert_eq!(txs[0]["sigops"], 4);
    assert_eq!(txs[0]["fee"], 1_000);
    let lp = tmpl["longpollid"].clone();
    let again = dispatch(ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    assert_eq!(again["longpollid"], lp);
    let stale = dispatch(
        ctx,
        "getblocktemplate",
        vec![json!({"rules": ["segwit"], "longpollid": "0000000000000000000000000000000000000000000000000000000000000000"})],
    )
    .unwrap();
    assert_eq!(stale["longpollid"], lp);

    // P2SH and P2WSH `OP_3 OP_CHECKMULTISIG` spends: Core GBT `sigops` is the
    // full cost (3 * 4 P2SH + 3 witness = 15); legacy-only counting gives 0.
    let ms = ScriptBuf::from_bytes(vec![0x53, 0xae]);
    let b = cbs.take();
    let cb_b = generated_coinbase_value(ctx, b);
    let mut fund = spend_generated_coinbase(ctx, b, cb_b / 2 - 1_000, ms.to_p2sh()).1;
    fund.output.push(TxOut {
        value: Amount::from_sat(cb_b / 2 - 1_000),
        script_pubkey: ms.to_p2wsh(),
    });
    dispatch(ctx, "sendrawtransaction", vec![json!(tx_hex(&fund))]).unwrap();
    let pk = [0x02u8; 33];
    let mut p2sh_sig = bitcoin::script::Builder::new().push_int(0).push_int(0);
    for _ in 0..3 {
        p2sh_sig = p2sh_sig.push_slice(pk);
    }
    let p2sh_sig = p2sh_sig
        .push_slice(<&bitcoin::script::PushBytes>::try_from(ms.as_bytes()).unwrap())
        .into_script();
    let wit = Witness::from_slice(&[&[][..], &[], &pk, &pk, &pk, ms.as_bytes()]);
    let fid = fund.compute_txid();
    let ms_spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint { txid: fid, vout: 0 },
                script_sig: p2sh_sig,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint { txid: fid, vout: 1 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: wit,
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(cb_b - 4_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let ms_id = dispatch(ctx, "sendrawtransaction", vec![json!(tx_hex(&ms_spend))]).unwrap();
    let tmpl = dispatch(ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    let ms_json = tmpl["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["txid"] == ms_id)
        .expect("ms spend");
    assert_eq!(ms_json["sigops"], 15);
    dispatch(ctx, "generate", vec![json!(1)]).unwrap();
    assert_eq!(dispatch(ctx, "getrawmempool", vec![]).unwrap(), json!([]));

    // A confirmed bare OP_CHECKSIG spent with a non-DER signature.
    let prev = checksig.compute_txid();
    let mut bad_sig = checksig.clone();
    bad_sig.input[0].previous_output = OutPoint { txid: prev, vout: 0 };
    bad_sig.input[0].script_sig = bitcoin::script::Builder::new()
        .push_slice([0x30u8, 0x01, 0x01, 0x01])
        .push_slice(pk)
        .into_script();
    bad_sig.output[0].value = Amount::from_sat(cb_a - 2_000);
    let reason = "mempool-script-verify-flag-failed (Non-canonical DER signature)";
    let tma = dispatch(ctx, "testmempoolaccept", vec![json!([tx_hex(&bad_sig)])]).unwrap();
    assert_eq!(tma[0]["allowed"], false, "{tma}");
    assert_eq!(tma[0]["reject-reason"], reason, "{tma}");
    assert_eq!(
        tma[0]["reject-details"],
        format!(
            "{reason}, input 0 of {} (wtxid {}), spending {prev}:0",
            bad_sig.compute_txid(),
            bad_sig.compute_wtxid(),
        ),
        "{tma}"
    );
    let e = dispatch(ctx, "sendrawtransaction", vec![json!(tx_hex(&bad_sig))]).unwrap_err();
    assert_eq!(e["code"], ERR_VERIFY_REJECTED);
    assert_eq!(e["message"], reason);
}

/// Ten bare 20-sigop outputs: cost 800, policy size 4_000 vB at 20 B/sigop.
fn sigop_heavy_spend(ctx: &RpcContext, height: u32, fee: u64) -> Transaction {
    use bitcoin::TxOut;
    let cb = generated_coinbase_value(ctx, height);
    let mut tx = spend_generated_coinbase(ctx, height, 0, ScriptBuf::new()).1;
    tx.output = vec![
        TxOut {
            value: Amount::from_sat(1_000),
            // OP_0 OP_0 OP_0 OP_NOP OP_CHECKMULTISIG OP_1: 20 legacy sigops.
            script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x00, 0x00, 0x61, 0xae, 0x51]),
        };
        10
    ];
    tx.output[0].value = Amount::from_sat(cb - fee - 9_000);
    assert_eq!(
        rbitcoin_consensus::tx_sigop_cost(&tx, &[], false, false),
        800
    );
    tx
}

fn chain_ops_restore_sigop_mining_knobs(ctx: &RpcContext) {
    // Hub opened at graph default 20 B/sigop and blockmintxfee 1 sat/kvB.
    ctx.mempool.as_ref().unwrap().set_bytes_per_sigop(20);
    ctx.chain
        .as_ref()
        .unwrap()
        .set_block_min_tx_fee_sat_kvb(1);
}

fn chain_ops_mine_pool_empty(ctx: &RpcContext) {
    for _ in 0..4 {
        if dispatch(ctx, "getrawmempool", vec![])
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty()
        {
            return;
        }
        dispatch(ctx, "generate", vec![json!(1)]).unwrap();
    }
    assert_eq!(dispatch(ctx, "getrawmempool", vec![]).unwrap(), json!([]));
}

/// `getmempoolentry` vsize is sigop-adjusted; weight and the Esplora/Electrum
/// surfaces stay raw. `blockmintxfee` uses the adjusted size.
fn chain_ops_sigop_adjusted_entry_and_min_fee(ctx: &RpcContext, cbs: &mut TrueCoinbases) {
    let tx = sigop_heavy_spend(ctx, cbs.take(), 2_000);
    let tid = tx.compute_txid();
    let tid_hex = tid.to_string();
    let tma = dispatch(ctx, "testmempoolaccept", vec![json!([tx_hex(&tx)])]).unwrap();
    assert_eq!(tma[0]["allowed"], true, "{tma}");
    assert_rpc_vsizes(&tma[0], &tx, 4_000);
    let height = cbs.take();
    let ordinary = spend_generated_coinbase(
        ctx,
        height,
        generated_coinbase_value(ctx, height) - 1_000,
        ScriptBuf::new(),
    )
    .1;
    let tma = dispatch(
        ctx,
        "testmempoolaccept",
        vec![json!([tx_hex(&tx), tx_hex(&ordinary)])],
    )
    .unwrap();
    assert_rpc_vsizes(&tma[0], &tx, 4_000);
    assert_rpc_vsizes(&tma[1], &ordinary, ordinary.vsize() as u64);
    assert_eq!(dispatch(ctx, "getrawmempool", vec![]).unwrap(), json!([]));
    for _ in 0..2 {
        let submitted = dispatch(ctx, "submitpackage", vec![json!([tx_hex(&tx)])]).unwrap();
        assert_eq!(submitted["package_msg"], "success", "{submitted}");
        assert_rpc_vsizes(
            &submitted["tx-results"][tx.compute_wtxid().to_string()],
            &tx,
            4_000,
        );
    }
    let raw_w = tx.weight().to_wu();
    assert!(raw_w < 16_000);
    let e = dispatch(
        ctx,
        "getmempoolentry",
        vec![json!(hash_hex_display(&tid.to_byte_array()))],
    )
    .unwrap();
    assert_rpc_vsizes(&e, &tx, 4_000);
    assert_eq!(e["weight"], raw_w);
    assert_eq!(e["ancestorsize"], 4_000);
    let verbose = dispatch(ctx, "getrawmempool", vec![json!(true)]).unwrap();
    assert_rpc_vsizes(&verbose[&tid_hex], &tx, 4_000);
    let raw = dispatch(ctx, "getrawtransaction", vec![json!(tid_hex), json!(2)]).unwrap();
    assert_eq!(raw["vsize"], tx.vsize());
    assert_eq!(raw["vsize_adjusted"], 4_000);
    assert!(raw.get("vsize_bip141").is_none());
    assert_eq!(
        dispatch(ctx, "getrawtransaction", vec![json!(tid_hex)]).unwrap(),
        tx_hex(&tx),
    );
    let decoded = dispatch(ctx, "decoderawtransaction", vec![json!(tx_hex(&tx))]).unwrap();
    assert_eq!(decoded["vsize"], tx.vsize());
    assert!(decoded.get("vsize_adjusted").is_none());
    let info = dispatch(ctx, "getmempoolinfo", vec![]).unwrap();
    assert_eq!(
        (info["size"].clone(), info["bytes"].clone()),
        (json!(1), json!(4_000))
    );
    assert_eq!(
        serde_json::to_string(&info["total_fee"]).unwrap(),
        "0.00002000"
    );
    // Newest accept: the journey already admitted earlier spends into this ring.
    let recent = ctx.mempool.as_ref().unwrap().recent_accepts();
    assert_eq!(
        recent.first().map(|r| (r.txid, r.weight)),
        Some((tid, raw_w))
    );
    let mp = ctx.mempool.as_ref().unwrap();
    let raw_vb = raw_w.div_ceil(4);
    assert_eq!(mp.fee_histogram(), vec![(500, raw_vb)]);
    assert_eq!(mp.mempool_live_totals(), (1, raw_vb, 2_000));

    let keep = |min| {
        ctx.chain
            .as_ref()
            .unwrap()
            .set_block_min_tx_fee_sat_kvb(min);
        rbitcoin_rpc::methods::mine::mempool_block_txs(ctx)
            .into_iter()
            .map(|(tx, _)| Transaction::clone(&tx))
            .collect::<Vec<_>>()
    };
    // 2_000 sat is 0.5 sat/vB at 4_000 vB.
    assert_eq!(keep(500), vec![tx.clone()]);
    assert_eq!(keep(501), Vec::<Transaction>::new());
    ctx.mempool.as_ref().unwrap().set_bytes_per_sigop(0);
    let unadjusted = dispatch(ctx, "getmempoolentry", vec![json!(tid_hex)]).unwrap();
    assert_rpc_vsizes(&unadjusted, &tx, tx.vsize() as u64);
    assert_eq!(keep(501), vec![tx]);
    chain_ops_restore_sigop_mining_knobs(ctx);
    chain_ops_mine_pool_empty(ctx);
    let confirmed = dispatch(ctx, "getrawtransaction", vec![json!(tid_hex), json!(true)]).unwrap();
    assert_eq!(confirmed["vsize"], raw_vb);
    assert!(confirmed["confirmations"].as_u64().unwrap() > 0);
    assert!(confirmed.get("vsize_adjusted").is_none());
}

fn assert_rpc_vsizes(row: &Value, tx: &Transaction, adjusted: u64) {
    assert_eq!(row["vsize"], adjusted, "{row}");
    assert_eq!(row["vsize_adjusted"], adjusted, "{row}");
    assert_eq!(row["vsize_bip141"], tx.vsize(), "{row}");
}

/// Package-retry `vsize` is sigop-adjusted. The zero-fee parent fails min
/// relay alone and is admitted with its paying child.
fn chain_ops_submitpackage_sigop_vsize(ctx: &RpcContext, cbs: &mut TrueCoinbases) {
    use bitcoin::{OutPoint, Sequence, TxIn, TxOut, Witness};
    let h = cbs.take();
    let cb = generated_coinbase_value(ctx, h);
    let mut parent = spend_generated_coinbase(ctx, h, 0, ScriptBuf::new()).1;
    parent.output = vec![
        TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x00, 0x00, 0x61, 0xae, 0x51]),
        };
        11
    ];
    parent.output[0] = TxOut {
        value: Amount::from_sat(cb - 10_000),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    };
    let mut child = parent.clone();
    child.input = vec![TxIn {
        previous_output: OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }];
    child.output = vec![TxOut {
        value: Amount::from_sat(cb - 10_000 - 50_000),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    }];
    let hexes = [&parent, &child].map(|t| json!(tx_hex(t)));
    let r = dispatch(ctx, "submitpackage", vec![json!(hexes)]).unwrap();
    assert_eq!(r["package_msg"], "success", "{r}");
    let row = |t: &Transaction| {
        r["tx-results"][hash_hex_display(&t.compute_wtxid().to_byte_array())].clone()
    };
    assert!(parent.weight().to_wu() < 16_000);
    assert_rpc_vsizes(&row(&parent), &parent, 4_000);
    assert_rpc_vsizes(&row(&child), &child, child.vsize() as u64);
    chain_ops_mine_pool_empty(ctx);
}

/// Core `CreateBigSigOpsCluster`: 1 parent + 50 children, legacy cost
/// 20_001 * 4. The template stays under the block sigop budget.
fn chain_ops_big_sigops_cluster(ctx: &RpcContext, cbs: &mut TrueCoinbases) {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::script::Builder;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{CompactTarget, OutPoint, Sequence, TxIn, TxMerkleNode, TxOut, Witness};
    let h = cbs.take();
    let cb_val = generated_coinbase_value(ctx, h);
    let mut parent = spend_generated_coinbase(ctx, h, 0, ScriptBuf::new()).1;
    // OP_0 OP_0 OP_CHECKSIG OP_1: one legacy sigop in the scriptSig.
    parent.input[0].script_sig = ScriptBuf::from_bytes(vec![0x00, 0x00, 0xac, 0x51]);
    parent.output = (0..50)
        .map(|_| TxOut {
            value: Amount::from_sat(cb_val / 50),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        })
        .collect();
    parent.output[0].value -= Amount::from_sat(100_000);
    let pid = parent.compute_txid();
    let mut txs = vec![parent];
    for i in 0..50u32 {
        let mut out = vec![
            TxOut {
                value: Amount::from_sat(1_000),
                // OP_0 OP_0 OP_0 OP_NOP OP_CHECKMULTISIG OP_1: 20 legacy sigops.
                script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x00, 0x00, 0x61, 0xae, 0x51]),
            };
            20
        ];
        let fee = 10_000 + 100 * u64::from(50 - i);
        out[0].value = txs[0].output[i as usize].value - Amount::from_sat(fee + 19_000);
        txs.push(Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: pid, vout: i },
                script_sig: ScriptBuf::from_bytes(vec![0x51]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: out,
        });
    }
    let legacy: u64 = txs
        .iter()
        .map(|t| rbitcoin_consensus::tx_sigop_cost(t, &[], false, false))
        .sum();
    assert_eq!(legacy, 20_001 * 4);
    for t in &txs {
        dispatch(ctx, "sendrawtransaction", vec![json!(tx_hex(t))]).unwrap();
    }

    let tmpl = dispatch(ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    let ttxs = tmpl["transactions"].as_array().unwrap();
    let sigops: u64 = ttxs.iter().map(|t| t["sigops"].as_u64().unwrap()).sum();
    // Parent + 49 children: 400 + 4 + 49 * 1_600 < 80_000; a 50th reaches 80_404.
    assert_eq!(ttxs.len(), 50, "{tmpl}");
    assert_eq!(sigops, 4 + 49 * 1_600);
    assert!(sigops <= 80_000 - 400);

    let next_h = tmpl["height"].as_u64().unwrap();
    let coinbase = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Builder::new()
                .push_int(next_h as i64)
                .push_int(1)
                .into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(tmpl["coinbasevalue"].as_u64().unwrap()),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let mut txdata = vec![coinbase];
    for t in ttxs {
        let raw = rbitcoin_primitives::hex_decode(t["data"].as_str().unwrap()).unwrap();
        txdata.push(deserialize(&raw).unwrap());
    }
    let prev = parse_hash32_display(tmpl["previousblockhash"].as_str().unwrap()).unwrap();
    let mut block = Block {
        header: Header {
            version: BlockVersion::from_consensus(tmpl["version"].as_i64().unwrap() as i32),
            prev_blockhash: bitcoin::BlockHash::from_byte_array(prev),
            merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
            time: tmpl["curtime"].as_u64().unwrap() as u32,
            bits: CompactTarget::from_consensus(
                u32::from_str_radix(tmpl["bits"].as_str().unwrap(), 16).unwrap(),
            ),
            nonce: 0,
        },
        txdata,
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    assert_eq!(rbitcoin_rpc::methods::mine::gbt_check_proposal(ctx, &block), Ok(()));
    chain_ops_mine_pool_empty(ctx);
}

fn chain_ops_prioritise(ctx: &RpcContext, cbs: &mut TrueCoinbases) {
    let c = cbs.take();
    let (hex, spend) =
        spend_generated_coinbase(ctx, c, generated_coinbase_value(ctx, c) - 1_000, true_spk());
    let tid = dispatch(ctx, "sendrawtransaction", vec![json!(hex)]).unwrap();
    let t = tid.as_str().unwrap();
    dispatch(ctx, "prioritisetransaction", vec![tid.clone(), json!(0), json!(-1_000)]).unwrap();
    let pri = dispatch(ctx, "getprioritisedtransactions", vec![]).unwrap();
    assert_eq!(pri[t]["fee_delta"], -1_000);
    assert_eq!(pri[t]["in_mempool"], true);
    dispatch(ctx, "generate", vec![json!(1)]).unwrap();
    assert_eq!(
        dispatch(ctx, "getrawmempool", vec![]).unwrap(),
        json!([tid]),
        "deprioritised tx stays unmined"
    );

    let entry = dispatch(ctx, "getmempoolentry", vec![tid.clone()]).unwrap();
    assert!(entry["fees"]["chunk"].is_number());
    assert_eq!(entry["chunkweight"], entry["weight"]);
    let cluster = dispatch(ctx, "getmempoolcluster", vec![tid.clone()]).unwrap();
    assert_eq!(cluster["txcount"], 1);
    assert_eq!(cluster["chunks"][0]["txs"], json!([tid]));
    let missing = dispatch(ctx, "getmempoolcluster", vec![json!("11".repeat(32))]).unwrap_err();
    assert_eq!(missing["code"], ERR_INVALID_ADDRESS_OR_KEY);
    assert_eq!(
        dispatch(ctx, "getmempoolancestors", vec![tid.clone()]).unwrap(),
        json!([])
    );
    assert_eq!(
        dispatch(ctx, "getmempooldescendants", vec![tid.clone()]).unwrap(),
        json!([])
    );
    assert!(dispatch(ctx, "getmempoolfeeratediagram", vec![])
        .unwrap()
        .is_array());
    let prevout = spend.input[0].previous_output;
    let spending = dispatch(
        ctx,
        "gettxspendingprevout",
        vec![json!([{ "txid": prevout.txid.to_string(), "vout": 0 }])],
    )
    .unwrap();
    assert_eq!(spending[0]["spendingtxid"], tid);
    let info = dispatch(ctx, "getmempoolinfo", vec![]).unwrap();
    assert_eq!(info["optimal"], true);

    dispatch(ctx, "prioritisetransaction", vec![tid, json!(0), json!(1_000)]).unwrap();
    dispatch(ctx, "generate", vec![json!(1)]).unwrap();
    assert_eq!(
        dispatch(ctx, "getrawmempool", vec![]).unwrap(),
        json!([]),
        "a zero delta mines again"
    );
}

fn true_spk() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0x51])
}

fn gbt_txids(ctx: &RpcContext) -> Vec<String> {
    let tmpl = dispatch(ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    tmpl["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["txid"].as_str().unwrap().to_string())
        .collect()
}

fn assert_template_before(ids: &[String], earlier: &str, later: &str) {
    let a = ids.iter().position(|t| t == earlier);
    let b = ids.iter().position(|t| t == later);
    assert!(
        a.is_some() && b.is_some() && a.unwrap() < b.unwrap(),
        "{earlier} before {later} in {ids:?}"
    );
}

fn op_true_child(parent: &Transaction, vout: u32, fee: u64, nonce: u32) -> Transaction {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, TxIn, TxOut, Witness};
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent.compute_txid(),
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(0x8000_0000 | nonce),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: parent.output[vout as usize].value - Amount::from_sat(fee),
            script_pubkey: true_spk(),
        }],
    }
}

fn send_tx(ctx: &RpcContext, tx: &Transaction) -> String {
    dispatch(ctx, "sendrawtransaction", vec![json!(tx_hex(tx))])
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

/// `getblocktemplate` lists a cluster in linearization order: higher rate,
/// then higher fee, then the lesser txid. A negative `prioritisetransaction`
/// drops that child from the template.
fn chain_ops_template_orders_rate_then_fee(ctx: &RpcContext, cbs: &mut TrueCoinbases) {
    let h = cbs.take();
    let cb = generated_coinbase_value(ctx, h);
    let each = (cb - 10_000) / 2;
    let parent = parent_paying(ctx, h, each, true_spk(), true_spk());
    send_tx(ctx, &parent);
    let (hi_rate, lo_rate) = (1..400u32)
        .find_map(|n| {
            let hi = op_true_child(&parent, 0, 8_000, n);
            let lo = op_true_child(&parent, 1, 1_000, n + 400);
            (hi.compute_txid() > lo.compute_txid()).then_some((hi, lo))
        })
        .expect("higher-fee child txid after the lower-fee child");
    assert_eq!(hi_rate.weight(), lo_rate.weight());
    let hi_rate_id = send_tx(ctx, &hi_rate);
    let lo_rate_id = send_tx(ctx, &lo_rate);
    let ids = gbt_txids(ctx);
    assert_template_before(&ids, &hi_rate_id, &lo_rate_id);
    chain_ops_mine_pool_empty(ctx);

    let h = cbs.take();
    let cb = generated_coinbase_value(ctx, h);
    let each = (cb - 10_000) / 2;
    let parent = parent_paying(ctx, h, each, true_spk(), true_spk());
    send_tx(ctx, &parent);
    let a = op_true_child(&parent, 0, 2_000, 1);
    let b = op_true_child(&parent, 1, 2_000, 2);
    assert_eq!(a.weight(), b.weight());
    let a_id = send_tx(ctx, &a);
    let b_id = send_tx(ctx, &b);
    let (lesser, greater) = if a.compute_txid() < b.compute_txid() {
        (a_id, b_id)
    } else {
        (b_id, a_id)
    };
    let ids = gbt_txids(ctx);
    assert_template_before(&ids, &lesser, &greater);
    dispatch(
        ctx,
        "prioritisetransaction",
        vec![json!(lesser.clone()), json!(0), json!(-2_001)],
    )
    .unwrap();
    let ids = gbt_txids(ctx);
    assert!(
        !ids.iter().any(|t| t == &lesser),
        "a negative fee delta leaves the template: {ids:?}"
    );
    assert!(ids.iter().any(|t| t == &greater), "{ids:?}");
    dispatch(
        ctx,
        "prioritisetransaction",
        vec![json!(lesser), json!(0), json!(2_001)],
    )
    .unwrap();
    chain_ops_mine_pool_empty(ctx);

    // 400_000 sat at vsize 2000 and 200_000 sat at vsize 1000 floor to the
    // same sat/kvB. The higher fee is the later txid, so the fee compare is
    // what puts it first in the template.
    let h = cbs.take();
    let cb = generated_coinbase_value(ctx, h);
    let each = (cb - 10_000) / 2;
    let hi_lens = p2wsh_item_lens(2_000);
    let lo_lens = p2wsh_item_lens(1_000);
    let hi_proto = p2wsh_with_lens(bitcoin::OutPoint::null(), each, 400_000, 1, &hi_lens);
    let lo_proto = p2wsh_with_lens(bitcoin::OutPoint::null(), each, 200_000, 1, &lo_lens);
    assert_eq!(
        rbitcoin_consensus::policy::fee_rate_sat_per_kvb(400_000, hi_proto.weight().to_wu()),
        rbitcoin_consensus::policy::fee_rate_sat_per_kvb(200_000, lo_proto.weight().to_wu()),
    );
    let parent = parent_paying(ctx, h, each, p2wsh_spk(&hi_proto), p2wsh_spk(&lo_proto));
    let pid = parent.compute_txid();
    send_tx(ctx, &parent);
    let (hi, lo) = (1..400u32)
        .find_map(|n| {
            let hi = p2wsh_with_lens(
                bitcoin::OutPoint { txid: pid, vout: 0 },
                each,
                400_000,
                n,
                &hi_lens,
            );
            let lo = p2wsh_with_lens(
                bitcoin::OutPoint { txid: pid, vout: 1 },
                each,
                200_000,
                n + 400,
                &lo_lens,
            );
            (hi.compute_txid() > lo.compute_txid()).then_some((hi, lo))
        })
        .expect("higher-fee txid after the lower-fee sibling");
    let hi_id = send_tx(ctx, &hi);
    let lo_id = send_tx(ctx, &lo);
    let ids = gbt_txids(ctx);
    assert_template_before(&ids, &hi_id, &lo_id);
    chain_ops_mine_pool_empty(ctx);
}

fn chain_ops_generateblock_and_parent_first(ctx: &RpcContext, cbs: &mut TrueCoinbases) -> u32 {
    // Core `rpc_generate.py` generateblock reject strings and codes.
    let op_true = "raw(51)";
    let missing = "00".repeat(32);
    let e = dispatch(ctx, "generateblock", vec![json!(op_true), json!([missing])]).unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_ADDRESS_OR_KEY);
    assert_eq!(e["message"], format!("Transaction {missing} not in mempool."));
    let e = dispatch(ctx, "generateblock", vec![json!(op_true), json!(["0000"])]).unwrap_err();
    assert_eq!(e["code"], ERR_DESERIALIZATION);
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .starts_with("Transaction decode failed for 0000"),
        "{e}"
    );
    let e = dispatch(ctx, "generateblock", vec![json!("1234"), json!([])]).unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_ADDRESS_OR_KEY);
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .contains("Invalid address or descriptor"),
        "{e}"
    );
    let tpub = "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp";
    let e = dispatch(
        ctx,
        "generateblock",
        vec![json!(format!("pkh({tpub}/0/*)")), json!([])],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_PARAMETER);
    assert_eq!(
        e["message"],
        "Ranged descriptor not accepted. Maybe pass through deriveaddresses first?"
    );
    let e = dispatch(
        ctx,
        "generateblock",
        vec![json!(format!("pkh({tpub}/0'/0)")), json!([])],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_INVALID_ADDRESS_OR_KEY);
    assert_eq!(e["message"], "Cannot derive script without private keys");

    let d = cbs.take();
    let cb_d = generated_coinbase_value(ctx, d);
    let (parent_hex, parent) = spend_generated_coinbase(ctx, d, cb_d - 2_000, true_spk());
    let parent_id = dispatch(ctx, "sendrawtransaction", vec![json!(parent_hex)]).unwrap();
    let mut child = parent.clone();
    child.input[0].previous_output = bitcoin::OutPoint {
        txid: parent.compute_txid(),
        vout: 0,
    };
    child.output[0].value = Amount::from_sat(cb_d - 3_000);
    let e = dispatch(
        ctx,
        "generateblock",
        vec![json!(op_true), json!([tx_hex(&child), parent_id.clone()])],
    )
    .unwrap_err();
    assert_eq!(e["code"], ERR_VERIFY_ERROR);
    assert_eq!(
        e["message"],
        "TestBlockValidity failed: bad-txns-inputs-missingorspent"
    );

    let child_id = dispatch(ctx, "sendrawtransaction", vec![json!(tx_hex(&child))]).unwrap();
    // Core's mempool coins view: the parent output is spent by the child, so
    // it is not a UTXO. Without the mempool it was never a confirmed coin.
    for include_mempool in [true, false] {
        let out = dispatch(
            ctx,
            "gettxout",
            vec![parent_id.clone(), json!(0), json!(include_mempool)],
        )
        .unwrap();
        assert!(
            out.is_null(),
            "include_mempool={include_mempool}: mempool-spent parent output: {out}"
        );
    }
    let unconfirmed = dispatch(ctx, "gettxout", vec![child_id.clone(), json!(0)]).unwrap();
    assert_eq!(unconfirmed["confirmations"], 0, "{unconfirmed}");
    dispatch(ctx, "generate", vec![json!(1)]).unwrap();
    let tip = best_hash(ctx);
    let mined = dispatch(ctx, "getblock", vec![tip.clone(), json!(1)]).unwrap();
    let txids = mined["tx"].as_array().unwrap();
    assert_eq!(txids.len(), 3, "coinbase + parent + child: {mined}");
    assert_eq!(txids[1], parent_id);
    assert_eq!(txids[2], child_id);
    // The child's prevout is in the same block, the parent's in the store.
    let stats = dispatch(ctx, "getblockstats", vec![tip, json!(["totalfee", "ins"])]).unwrap();
    assert_eq!(stats, json!({"ins": 2, "totalfee": 3_000}));

    let cb_hex = parent.input[0].previous_output.txid.to_string();
    let spent = dispatch(ctx, "gettxout", vec![json!(cb_hex), json!(0)]).unwrap();
    assert!(spent.is_null(), "spent coinbase is not unspent: {spent}");
    let child_out = dispatch(ctx, "gettxout", vec![child_id.clone(), json!(0)]).unwrap();
    assert_eq!(child_out["coinbase"], false, "{child_out}");

    let young = tip_count(ctx) as u32 - 5;
    let (hex, _) =
        spend_generated_coinbase(ctx, young, generated_coinbase_value(ctx, young) - 1_000, true_spk());
    let e = dispatch(ctx, "sendrawtransaction", vec![json!(hex)]).unwrap_err();
    assert_eq!(e["code"], ERR_VERIFY_REJECTED);
    assert_eq!(e["message"], "bad-txns-premature-spend-of-coinbase");
    young + 5
}

fn chain_ops_proposal_spends(ctx: &RpcContext, cbs: &mut TrueCoinbases) {
    use bitcoin::absolute::LockTime;
    let f = cbs.take();
    let cb_f = generated_coinbase_value(ctx, f);
    let (hex, spend) = spend_generated_coinbase(ctx, f, cb_f - 1_000, true_spk());
    assert!(propose(ctx, &proposal_on_tip(ctx, vec![spend.clone()])).is_null());
    let mut bad_script = spend.clone();
    bad_script.input[0].script_sig = ScriptBuf::from_bytes(vec![0x00, 0x69]);
    let got = propose(ctx, &proposal_on_tip(ctx, vec![bad_script]));
    let reason = got.as_str().unwrap_or("");
    assert!(
        reason.starts_with("block-script-verify-flag-failed"),
        "a failing script must not validate: {got}"
    );
    assert_eq!(
        propose(ctx, &proposal_on_tip(ctx, vec![spend.clone(), spend.clone()])),
        "bad-txns-inputs-missingorspent",
        "a second copy spends the same coin"
    );
    let mut fat = spend.clone();
    fat.output[0].value = Amount::from_sat(cb_f + 1);
    assert_eq!(
        propose(ctx, &proposal_on_tip(ctx, vec![fat.clone()])),
        "bad-txns-in-belowout"
    );
    let mut fat_block = proposal_on_tip(ctx, vec![fat]);
    regrind(&mut fat_block);
    assert_eq!(
        dispatch(ctx, "submitblock", vec![json!(block_hex(&fat_block))]).unwrap(),
        "bad-txns-in-belowout",
        "a mature coin with outputs above its inputs"
    );
    let mut locked = spend.clone();
    locked.lock_time = LockTime::from_height(tip_count(ctx) as u32 + 50).unwrap();
    locked.input[0].sequence = bitcoin::Sequence::ZERO;
    assert_eq!(
        propose(ctx, &proposal_on_tip(ctx, vec![locked])),
        "bad-txns-nonfinal"
    );
    // BIP113: a time lock is final only below the parent's median time,
    // not below this block's own stamp.
    let tip_mtp = dispatch(ctx, "getblockheader", vec![best_hash(ctx), json!(true)]).unwrap()
        ["mediantime"]
        .as_u64()
        .unwrap() as u32;
    let mut time_locked = spend.clone();
    time_locked.lock_time = LockTime::from_time(tip_mtp).unwrap();
    time_locked.input[0].sequence = bitcoin::Sequence::ZERO;
    let block = proposal_on_tip(ctx, vec![time_locked.clone()]);
    assert!(block.header.time > tip_mtp);
    assert_eq!(propose(ctx, &block), "bad-txns-nonfinal", "BIP113");
    time_locked.lock_time = LockTime::from_time(tip_mtp - 1).unwrap();
    assert!(
        propose(ctx, &proposal_on_tip(ctx, vec![time_locked])).is_null(),
        "BIP113: one second below the median is final"
    );
    // BIP68: the coin at height `f` is `age` deep in the proposed block.
    let age = tip_count(ctx) as u32 + 1 - f;
    let mut rel = spend.clone();
    rel.input[0].sequence = bitcoin::Sequence::from_height(age as u16);
    assert!(propose(ctx, &proposal_on_tip(ctx, vec![rel.clone()])).is_null());
    rel.input[0].sequence = bitcoin::Sequence::from_height(age as u16 + 1);
    assert_eq!(
        propose(ctx, &proposal_on_tip(ctx, vec![rel])),
        "bad-txns-nonfinal",
        "BIP68 height lock one block short"
    );
    let mut rel_time = spend.clone();
    rel_time.input[0].sequence = bitcoin::Sequence::from_512_second_intervals(0);
    assert!(
        propose(ctx, &proposal_on_tip(ctx, vec![rel_time.clone()])).is_null(),
        "a met time lock reads the coin's median time"
    );
    rel_time.input[0].sequence = bitcoin::Sequence::from_512_second_intervals(u16::MAX);
    assert_eq!(
        propose(ctx, &proposal_on_tip(ctx, vec![rel_time])),
        "bad-txns-nonfinal",
        "BIP68 time lock"
    );
    // A coin created in the proposed block is at that block's height.
    let mut child = spend.clone();
    child.input[0].previous_output = bitcoin::OutPoint {
        txid: spend.compute_txid(),
        vout: 0,
    };
    child.input[0].sequence = bitcoin::Sequence::from_height(0);
    child.output[0].value = spend.output[0].value - Amount::from_sat(1_000);
    assert!(propose(ctx, &proposal_on_tip(ctx, vec![spend.clone(), child.clone()])).is_null());
    child.input[0].sequence = bitcoin::Sequence::from_height(1);
    assert_eq!(
        propose(ctx, &proposal_on_tip(ctx, vec![spend.clone(), child])),
        "bad-txns-nonfinal",
        "a same-block coin is zero blocks deep"
    );
    let mut ghost = spend.clone();
    ghost.input[0].previous_output.txid = Txid::from_byte_array([0xab; 32]);
    assert_eq!(
        propose(ctx, &proposal_on_tip(ctx, vec![ghost])),
        "bad-txns-inputs-missingorspent"
    );
    dispatch(ctx, "sendrawtransaction", vec![json!(hex)]).unwrap();
    dispatch(ctx, "generate", vec![json!(1)]).unwrap();
    assert_eq!(
        propose(ctx, &proposal_on_tip(ctx, vec![spend.clone()])),
        "bad-txns-inputs-missingorspent",
        "a coin a block spent is gone from the proposal view"
    );

    // Each output is MAX_MONEY, so CheckBlock's per-output gate passes, but
    // the sum does not fit in u64. Proposal mode must not return success.
    use bitcoin::TxOut;
    const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
    let mut overflow = spend.clone();
    overflow.output = (0..8785)
        .map(|_| TxOut {
            value: Amount::from_sat(MAX_MONEY),
            script_pubkey: true_spk(),
        })
        .collect();
    let got = propose(ctx, &proposal_on_tip(ctx, vec![overflow]));
    let reason = got.as_str().unwrap_or("");
    assert!(
        reason == "bad-txns-inputvalues-outofrange"
            || reason == "bad-txns-txouttotal-toolarge"
            || reason == "bad-txns-fee-outofrange",
        "overflowing output sum must not validate: {got}"
    );
}

/// Core reports a repeated txid by where it fails: a repeat that keeps the
/// merkle root is a mutated body (CheckMerkleRoot), a second coinbase is
/// CheckBlock's `bad-cb-multiple`, and any other repeat spends a spent coin.
fn chain_ops_submit_repeated_txids(
    ctx: &RpcContext,
    hub: &rbitcoin_net::ChainHub,
    cbs: &mut TrueCoinbases,
) {
    let f = cbs.take();
    let cb_f = generated_coinbase_value(ctx, f);
    let (_, spend) = spend_generated_coinbase(ctx, f, cb_f - 1_000, true_spk());
    let h = tip_count(ctx) as u32 + 1;
    let time = hub.tip_header().unwrap().time + 1;
    let mine = |height: u32, extra: Vec<Transaction>| {
        rbitcoin_consensus::mine_regtest_paying(
            hub.tip_hash().unwrap(),
            time,
            height,
            true_spk(),
            extra,
        )
    };
    let mut mutated = mine(h, vec![]);
    mutated.txdata.push(mutated.txdata[0].clone());
    mutated.header.merkle_root = mutated.compute_merkle_root().unwrap();
    regrind(&mut mutated);
    let other_cb = mine(h + 1, vec![]).txdata[0].clone();
    let before = tip_count(ctx);
    for (block, want) in [
        (mutated, "bad-txns-duplicate"),
        (mine(h, vec![other_cb]), "bad-cb-multiple"),
        (
            mine(h, vec![spend.clone(), spend.clone()]),
            "bad-txns-inputs-missingorspent",
        ),
    ] {
        let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&block))]).unwrap();
        assert_eq!(r, want);
    }
    assert_eq!(tip_count(ctx), before);
}

/// Witness bytes weigh one unit each, so a block under the stripped-size cap
/// can still pass MAX_BLOCK_WEIGHT: Core ContextualCheckBlock `bad-blk-weight`.
fn chain_ops_submit_overweight(
    ctx: &RpcContext,
    hub: &rbitcoin_net::ChainHub,
    cbs: &mut TrueCoinbases,
) {
    // Two spends: one witness may not exceed rust-bitcoin's 4 MB decode cap.
    let heavy: Vec<Transaction> = (0..2)
        .map(|_| {
            let f = cbs.take();
            let cb_f = generated_coinbase_value(ctx, f);
            let (_, mut tx) = spend_generated_coinbase(ctx, f, cb_f - 1_000, true_spk());
            tx.input[0].witness = bitcoin::Witness::from_slice(&vec![vec![0u8; 4_000]; 525]);
            tx
        })
        .collect();
    let block = rbitcoin_consensus::mine_regtest_paying(
        hub.tip_hash().unwrap(),
        hub.tip_header().unwrap().time + 1,
        tip_count(ctx) as u32 + 1,
        true_spk(),
        heavy,
    );
    assert!(block.weight().to_wu() > 4_000_000);
    let before = tip_count(ctx);
    let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&block))]).unwrap();
    assert_eq!(r, "bad-blk-weight");
    assert_eq!(tip_count(ctx), before);
}

fn chain_ops_maxfeerate(ctx: &RpcContext, cbs: &mut TrueCoinbases) {
    let heights: Vec<u32> = (0..8).map(|_| cbs.take()).collect();
    pin_sendraw_maxfeerate_at_default_and_one_sat_over(ctx, heights[0], heights[1]);
    let (hex, spend) = spend_generated_coinbase(ctx, heights[2], 1_000, true_spk());
    let e = dispatch(ctx, "sendrawtransaction", vec![json!(hex.clone())]).unwrap_err();
    assert_eq!(e["code"], ERR_VERIFY_ERROR, "{e}");
    assert!(
        e["message"]
            .as_str()
            .unwrap_or("")
            .contains("maximum configured by user"),
        "{e}"
    );
    let tma = dispatch(ctx, "testmempoolaccept", vec![json!([hex.clone()])]).unwrap();
    assert_eq!(tma[0]["allowed"], false, "{tma}");
    assert_eq!(tma[0]["reject-reason"], "max-fee-exceeded", "{tma}");
    let tma0 = dispatch(ctx, "testmempoolaccept", vec![json!([hex.clone()]), json!(0)]).unwrap();
    assert_eq!(tma0[0]["allowed"], true, "{tma0}");
    ctx.mempool
        .as_ref()
        .unwrap()
        .accept_tx(&spend)
        .expect("P2P/admit path is not capped by RPC maxfeerate");
    let ok = dispatch(ctx, "sendrawtransaction", vec![json!(hex.clone()), json!(0)]).unwrap();
    assert!(ok.as_str().is_some(), "{ok}");
    let over = dispatch(ctx, "sendrawtransaction", vec![json!(hex), json!(1)]).unwrap_err();
    assert_eq!(over["code"], ERR_INVALID_PARAMETER, "{over}");
    assert_eq!(
        over["message"],
        "Fee rates larger than or equal to 1BTC/kvB are not accepted"
    );

    let modest_at = |h: u32| {
        spend_generated_coinbase(ctx, h, generated_coinbase_value(ctx, h) - 1_000, true_spk())
    };
    let (modest_hex, modest) = modest_at(heights[3]);
    let ok99 = dispatch(
        ctx,
        "sendrawtransaction",
        vec![json!(modest_hex), json_num("0.99999999")],
    )
    .unwrap();
    assert_eq!(ok99, json!(modest.compute_txid().to_string()));
    pin_maxfeerate_json_shapes(ctx);
    let (str_hex, str_tx) = modest_at(heights[4]);
    let ok_str =
        dispatch(ctx, "sendrawtransaction", vec![json!(str_hex), json!("0.99999999")]).unwrap();
    assert_eq!(ok_str, json!(str_tx.compute_txid().to_string()));
    pin_maxfeerate_core_rounding(ctx, heights[6]);
    pin_maxfeerate_size_and_fee_basis(ctx, heights[7]);

    let (huge_hex, _) = spend_generated_coinbase(ctx, heights[5], 1_000, true_spk());
    let pkg = dispatch(ctx, "submitpackage", vec![json!([huge_hex])]).unwrap();
    assert_eq!(pkg["package_msg"], "transaction failed", "{pkg}");
    let row = pkg["tx-results"].as_object().unwrap().values().next().unwrap();
    assert_eq!(row["error"], "max feerate exceeded", "{pkg}");
    let again = dispatch(ctx, "submitpackage", vec![json!([tx_hex(&modest)])]).unwrap();
    assert_eq!(again["package_msg"], "success", "{again}");
    let row = again["tx-results"].as_object().unwrap().values().next().unwrap();
    assert!(row.get("error").is_none(), "already-in-mempool: {again}");
    assert_eq!(row["txid"], json!(modest.compute_txid().to_string()));
    assert!(row.get("vsize").is_some() && row["fees"].get("base").is_some(), "{again}");
    dispatch(ctx, "generate", vec![json!(1)]).unwrap();
    assert_eq!(dispatch(ctx, "getrawmempool", vec![]).unwrap(), json!([]));
}

/// `maxfeerate` is BTC/kvB, carried at Core's 1 sat/kvB resolution. Core
/// rounds its two checks differently: `sendrawtransaction` and
/// `testmempoolaccept` cap the fee at `GetFee(vsize)`, rounded up to a whole
/// sat; `submitpackage` compares each member's feerate unrounded.
fn pin_maxfeerate_core_rounding(ctx: &RpcContext, height: u32) {
    let cb = generated_coinbase_value(ctx, height);
    let probe = spend_generated_coinbase(ctx, height, cb - 1, true_spk()).1;
    let vsize = bitcoin::Weight::from_wu(probe.weight().to_wu()).to_vbytes_ceil();
    // At 1001 sat/kvB the `GetFee` cap is ceil(1.001 * vsize) = vsize + 1.
    assert!(vsize < 1000, "{vsize}");
    let (hex, tx) = spend_generated_coinbase(ctx, height, cb - (vsize + 1), true_spk());
    let tma = |rate: Value| {
        dispatch(ctx, "testmempoolaccept", vec![json!([hex.clone()]), rate]).unwrap()[0].clone()
    };
    // 1 sat/kvB is the smallest cap, not unlimited. Python and Go write
    // small floats in exponent form; Core `ParseFixedPoint` reads it.
    for tight in [
        json_num("0.00000001"),
        json_num("1e-08"),
        json!("1E-8"),
        json!("0.00001000"),
        json_num("1e-05"),
    ] {
        let row = tma(tight.clone());
        assert_eq!(row["reject-reason"], "max-fee-exceeded", "{tight}: {row}");
    }
    for exact in [json_num("0.00001001"), json_num("1.001e-05")] {
        let row = tma(exact.clone());
        assert_eq!(row["allowed"], true, "{exact}: {row}");
    }
    // The parent fails that unrounded check before admit, so its child is
    // missing inputs, as in Core `rpc_packages.py`.
    let child = child_of(&tx, 1_000);
    let pkg = dispatch(
        ctx,
        "submitpackage",
        vec![json!([hex.clone(), tx_hex(&child)]), json!("0.00001001")],
    )
    .unwrap();
    let rows = &pkg["tx-results"];
    let w = |t: &Transaction| t.compute_wtxid().to_string();
    assert_eq!(rows[w(&tx)]["error"], "max feerate exceeded", "{pkg}");
    assert_eq!(rows[w(&child)]["error"], "bad-txns-inputs-missingorspent", "{pkg}");
    let ok = dispatch(
        ctx,
        "sendrawtransaction",
        vec![json!(hex), json_num("0.00001001")],
    )
    .unwrap();
    assert_eq!(ok, json!(tx.compute_txid().to_string()));
}

/// Core sizes the cap three ways. `sendrawtransaction` takes the base fee
/// over BIP141 vsize, `testmempoolaccept` the base fee over sigop-adjusted
/// vsize, and `submitpackage` the modified fee over sigop-adjusted vsize.
fn pin_maxfeerate_size_and_fee_basis(ctx: &RpcContext, height: u32) {
    use bitcoin::TxOut;
    let cb = generated_coinbase_value(ctx, height);
    let mut tx = spend_generated_coinbase(ctx, height, 0, true_spk()).1;
    // OP_0 OP_0 OP_0 OP_NOP OP_CHECKMULTISIG OP_1: 20 legacy sigops each,
    // so 10 of them are an 800 sigop cost and a 4_000 vB adjusted size.
    tx.output = vec![
        TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x00, 0x00, 0x61, 0xae, 0x51]),
        };
        11
    ];
    // 1 sat/vB over the adjusted size.
    let fee = 4_000;
    tx.output[0] = TxOut {
        value: Amount::from_sat(cb - 10_000 - fee),
        script_pubkey: true_spk(),
    };
    assert!(tx.vsize() * 10 < 4_000, "{}", tx.vsize());
    let hex = tx_hex(&tx);
    let txid = tx.compute_txid().to_string();
    let rate = json!("0.00001");
    let e = dispatch(ctx, "sendrawtransaction", vec![json!(hex), rate.clone()]).unwrap_err();
    assert_eq!(e["code"], ERR_VERIFY_ERROR, "BIP141 vsize: {e}");
    let tma = dispatch(ctx, "testmempoolaccept", vec![json!([hex]), rate.clone()]).unwrap();
    assert_eq!(tma[0]["allowed"], true, "adjusted vsize: {tma}");
    let package = |delta: i64| {
        dispatch(ctx, "prioritisetransaction", vec![json!(txid), json!(0), json!(delta)]).unwrap();
        dispatch(ctx, "submitpackage", vec![json!([hex]), rate.clone()]).unwrap()
    };
    let over = package(1);
    let row = over["tx-results"].as_object().unwrap().values().next().unwrap();
    assert_eq!(row["error"], "max feerate exceeded", "modified fee: {over}");
    let ok = package(-1);
    assert_eq!(ok["package_msg"], "success", "{ok}");
    // A member already in the pool is not re-checked, so a delta that puts
    // it over the cap does not block its new child (Core `AcceptPackage`).
    let child_vb = child_of(&tx, 0).vsize() as u64;
    let child = child_of(&tx, child_vb);
    dispatch(ctx, "prioritisetransaction", vec![json!(txid), json!(0), json!(1)]).unwrap();
    let pkg = dispatch(
        ctx,
        "submitpackage",
        vec![json!([hex, tx_hex(&child)]), rate],
    )
    .unwrap();
    assert_eq!(pkg["package_msg"], "success", "{pkg}");
    assert!(ctx.mempool.as_ref().unwrap().contains(&child.compute_txid()), "{pkg}");
}

fn chain_ops_invalidate_and_precious(
    ctx: &RpcContext,
    hub: &rbitcoin_net::ChainHub,
    cbs: &mut TrueCoinbases,
    p2wpkh: &ScriptBuf,
) {
    let e = cbs.take();
    let (hex, _) =
        spend_generated_coinbase(ctx, e, generated_coinbase_value(ctx, e) - 1_000, true_spk());
    dispatch(ctx, "sendrawtransaction", vec![json!(hex.clone())]).unwrap();
    let tma = |hex: &str| {
        dispatch(ctx, "testmempoolaccept", vec![json!([hex]), json!(0)]).unwrap()[0].clone()
    };
    assert_eq!(tma(&hex)["reject-reason"], "txn-already-in-mempool");
    dispatch(ctx, "generate", vec![json!(1)]).unwrap();
    assert_eq!(tma(&hex)["reject-reason"], "txn-already-known");

    let tip_h = tip_count(ctx);
    let tip = best_hash(ctx);
    let blk = dispatch(ctx, "getblock", vec![tip.clone(), json!(1)]).unwrap();
    let cb_txid = blk["tx"][0].clone();
    let gettxout = || dispatch(ctx, "gettxout", vec![cb_txid.clone(), json!(0), json!(false)]).unwrap();
    assert_eq!(gettxout()["coinbase"], true);
    dispatch(ctx, "invalidateblock", vec![tip.clone()]).unwrap();
    assert_eq!(tip_count(ctx), tip_h - 1);
    assert!(gettxout().is_null(), "a disconnected Class A row is not a UTXO");
    let back = tma(&hex);
    assert_eq!(back["reject-reason"], "txn-already-in-mempool", "{back}");
    dispatch(ctx, "reconsiderblock", vec![tip.clone()]).unwrap();
    assert_eq!(tip_count(ctx), tip_h);
    assert_eq!(best_hash(ctx), tip);
    assert_eq!(tma(&hex)["reject-reason"], "txn-already-known");

    let (_, parent) = hub.query.header_at_height(Height(tip_h as u32 - 1)).unwrap().unwrap();
    let sibling = rbitcoin_consensus::mine_regtest_paying(
        BlockHash::from_byte_array(parent.hash),
        parent.timestamp + 900,
        tip_h as u32,
        p2wpkh.clone(),
        vec![],
    );
    let sib = json!(sibling.block_hash().to_string());
    assert_ne!(sib, tip);
    let parked = dispatch(ctx, "submitblock", vec![json!(block_hex(&sibling))]).unwrap();
    assert_eq!(parked, "inconclusive");
    assert_eq!(best_hash(ctx), tip);
    let tips = dispatch(ctx, "getchaintips", vec![]).unwrap();
    let tips = tips.as_array().unwrap();
    assert!(tips.iter().any(|t| t["status"] == "active" && t["hash"] == tip));
    assert!(tips.iter().any(|t| t["status"] == "valid-headers" && t["hash"] == sib));
    let held = dispatch(ctx, "getblock", vec![sib.clone(), json!(1)]).unwrap();
    assert_eq!(held["confirmations"], -1);
    assert!(held["difficulty"].as_f64().is_some(), "held difficulty: {held}");
    assert_eq!(held["versionHex"].as_str().expect("held versionHex").len(), 8);
    assert!(held.get("nextblockhash").is_none());

    dispatch(ctx, "preciousblock", vec![sib.clone()]).unwrap();
    assert_eq!(best_hash(ctx), sib);
    dispatch(ctx, "preciousblock", vec![tip.clone()]).unwrap();
    assert_eq!(best_hash(ctx), tip);
    let h1 = dispatch(ctx, "getblockhash", vec![json!(1)]).unwrap();
    dispatch(ctx, "preciousblock", vec![h1]).unwrap();
    assert_eq!(best_hash(ctx), tip, "precious of less work must not activate");
}

/// Core `reconsiderblock`: clear the marks, then activate the most-work
/// chain. Restored paths join into one branch, and a restored block that
/// loses stays a fork the next `invalidateblock` can return to.
fn chain_ops_reconsider_most_work(
    ctx: &RpcContext,
    hub: &rbitcoin_net::ChainHub,
    p2wpkh: &ScriptBuf,
) {
    let best = || best_hash(ctx).as_str().unwrap().parse::<BlockHash>().unwrap();
    let call = |method: &str, hash: BlockHash| {
        dispatch(ctx, method, vec![json!(hash.to_string())]).unwrap();
    };
    let generate = |n: u32| -> Vec<BlockHash> {
        let mined = dispatch(ctx, "generate", vec![json!(n)]).unwrap();
        let mined = mined.as_array().unwrap();
        mined.iter().map(|h| h.as_str().unwrap().parse().unwrap()).collect()
    };
    let side = |mut prev: BlockHash, n: u32| -> Vec<BlockHash> {
        let parent = dispatch(ctx, "getblockheader", vec![json!(prev.to_string())]).unwrap();
        let mut time = parent["time"].as_u64().unwrap() as u32;
        let mut height = parent["height"].as_u64().unwrap() as u32;
        let mut out = Vec::new();
        for _ in 0..n {
            time += 900;
            height += 1;
            let block =
                rbitcoin_consensus::mine_regtest_paying(prev, time, height, p2wpkh.clone(), vec![]);
            dispatch(ctx, "submitblock", vec![json!(block_hex(&block))]).unwrap();
            prev = block.block_hash();
            out.push(prev);
        }
        out
    };
    let status = |hash: BlockHash| {
        let tips = dispatch(ctx, "getchaintips", vec![]).unwrap();
        let tips = tips.as_array().unwrap();
        tips.iter()
            .find(|t| t["hash"] == json!(hash.to_string()))
            .map(|t| t["status"].as_str().unwrap().to_owned())
    };

    // a2 alone only ties b2. The two restored paths outweigh it together.
    let a = generate(3);
    call("invalidateblock", a[2]);
    call("invalidateblock", a[1]);
    let b = side(a[0], 1);
    assert_eq!(best(), b[0]);
    call("reconsiderblock", a[1]);
    assert_eq!(best(), a[2]);
    assert_eq!(status(b[0]).as_deref(), Some("valid-fork"));

    // a3..a4 loses to c3..c5 but stays a fork, so invalidating c3 returns
    // to a4. Only the leaf a4 is a tip.
    let a4 = generate(1)[0];
    call("invalidateblock", a4);
    call("invalidateblock", a[2]);
    assert_eq!(best(), a[1]);
    let c = side(a[1], 3);
    call("reconsiderblock", a[2]);
    assert_eq!(best(), c[2]);
    assert_eq!(status(a4).as_deref(), Some("valid-fork"));
    assert_eq!(status(a[2]), None, "a block under a4 is not a fork tip");
    assert_eq!(status(a[1]), None, "a connected block is not a fork tip");
    call("invalidateblock", c[0]);
    assert_eq!(best(), a4);

    // d7 and the sibling e7..e8 share the restored d5..d6.
    let d = generate(3);
    call("invalidateblock", d[2]);
    let e = side(d[1], 2);
    call("invalidateblock", e[0]);
    call("invalidateblock", d[0]);
    assert_eq!(best(), a4);
    call("reconsiderblock", d[0]);
    assert_eq!(best(), e[1]);
    assert_eq!(status(d[2]).as_deref(), Some("valid-fork"));

    // f2 is a fork tip after g2..g5 wins. The restored f3..f4 on top of it
    // was connected before, so f4 is a fork tip too. f2 stays one: with f3
    // invalid again, invalidating g2 returns to f2.
    let f = generate(4);
    call("invalidateblock", f[2]);
    let g = side(f[0], 4);
    assert_eq!(best(), g[3]);
    call("reconsiderblock", f[2]);
    assert_eq!(best(), g[3]);
    assert_eq!(status(f[3]).as_deref(), Some("valid-fork"));
    call("invalidateblock", f[2]);
    call("invalidateblock", g[0]);
    assert_eq!(best(), f[1]);
    call("reconsiderblock", f[2]);
    assert_eq!(best(), f[3]);

    // A held child that never connected does not hide its restored parent:
    // h4 under the invalid h5 is still a fork to return to. h5 comes from a
    // peer and is held under the invalidated h4 (Core's submitblock refuses
    // it as `bad-prevblk`).
    let h = generate(4);
    let top = dispatch(ctx, "getblockheader", vec![json!(h[3].to_string())]).unwrap();
    let mut bad = rbitcoin_consensus::mine_regtest_paying(
        h[3],
        top["time"].as_u64().unwrap() as u32 + 1,
        top["height"].as_u64().unwrap() as u32 + 1,
        p2wpkh.clone(),
        vec![],
    );
    let value = &mut bad.txdata[0].output[0].value;
    *value = bitcoin::Amount::from_sat(value.to_sat() + 1);
    bad.header.merkle_root = bad.compute_merkle_root().unwrap();
    rbitcoin_consensus::grind_regtest_pow(&mut bad.header);
    call("invalidateblock", h[2]);
    let _ = hub.accept_received_block(bad.clone());
    let i = side(h[0], 5);
    call("reconsiderblock", h[2]);
    assert_eq!(best(), i[4]);
    assert_eq!(status(h[3]).as_deref(), Some("valid-fork"));
    call("invalidateblock", bad.block_hash());
    call("invalidateblock", i[0]);
    assert_eq!(best(), h[3]);
}

/// A held body reports the height and chain work Core gives it, whether its
/// parent is on the active chain, held, or a stored side header. Each one
/// here ties the tip, so all are held.
fn chain_ops_held_height_and_work(
    ctx: &RpcContext,
    hub: &rbitcoin_net::ChainHub,
    p2wpkh: &ScriptBuf,
) {
    let tip = best_hash(ctx);
    let tip_h = tip_count(ctx) as u32;
    let at = |h: u32| hub.query.header_at_height(Height(h)).unwrap().unwrap().1;
    let mine = |prev: [u8; 32], time: u32, height: u32| {
        let prev = BlockHash::from_byte_array(prev);
        rbitcoin_consensus::mine_regtest_paying(prev, time, height, p2wpkh.clone(), vec![])
    };
    let submit = |b: &Block| dispatch(ctx, "submitblock", vec![json!(block_hex(b))]).unwrap();
    let (parent, base) = (at(tip_h - 1), at(tip_h - 2));
    let on_active = mine(parent.hash, parent.timestamp + 1000, tip_h);
    let held_parent = mine(base.hash, base.timestamp + 1001, tip_h - 1);
    let on_held = mine(held_parent.block_hash().to_byte_array(), base.timestamp + 1002, tip_h);
    let header_parent = mine(base.hash, base.timestamp + 1003, tip_h - 1);
    let on_header = mine(header_parent.block_hash().to_byte_array(), base.timestamp + 1004, tip_h);
    for b in [&on_active, &held_parent, &on_held] {
        assert_eq!(submit(b), "inconclusive");
    }
    let header = rbitcoin_primitives::hex_encode(bitcoin::consensus::encode::serialize(&header_parent.header));
    dispatch(ctx, "submitheader", vec![json!(header)]).unwrap();
    assert_eq!(submit(&on_header), "inconclusive");
    assert_eq!(best_hash(ctx), tip);
    let header_of = |h: BlockHash| {
        dispatch(ctx, "getblockheader", vec![json!(h.to_string())]).unwrap()
    };
    let at_tip = dispatch(ctx, "getblockheader", vec![tip]).unwrap();
    let below_tip = header_of(BlockHash::from_byte_array(parent.hash));
    for (b, want) in [
        (&on_active, &at_tip),
        (&held_parent, &below_tip),
        (&on_held, &at_tip),
        (&on_header, &at_tip),
    ] {
        let hash = json!(b.block_hash().to_string());
        let block = dispatch(ctx, "getblock", vec![hash, json!(1)]).unwrap();
        for got in [&header_of(b.block_hash()), &block] {
            assert_eq!(got["confirmations"], -1, "{got}");
            assert_eq!(got["height"], want["height"], "{got}");
            assert_eq!(got["chainwork"], want["chainwork"], "{got}");
        }
    }
}

/// Last beat, because it corrupts the store: a connected spend whose parent
/// edge in `input.body` is gone is a broken promise, not a txid lookup.
fn chain_ops_corrupt_input_edge(ctx: &RpcContext, store: &std::path::Path, height: u32) {
    use rbitcoin_primitives::Fk;
    use rbitcoin_store::TxStatRow;
    use std::io::{Seek, SeekFrom, Write};
    let fks = ctx.query.block_tx_fks(Height(height)).unwrap();
    let parent = fks[1];
    assert!(parent.0 < 1024, "one input.loc window: {parent:?}");
    let db = ctx.query.store();
    let unstamped = TxStatRow {
        fee_sat: 0,
        base: 0,
        wit_extra: 0,
    };
    for &fk in &fks {
        db.write_txstat_row(fk, &unstamped).unwrap();
    }
    assert!(ctx.query.stamped_txstat_block(Height(height)).unwrap().is_none());
    let earlier: u64 = (1..parent.0)
        .map(|id| db.input_edges(Fk(id)).unwrap().map_or(0, |e| e.len() as u64))
        .sum();
    let body = walk_for(store, "input.body").expect("input.body");
    let mut f = std::fs::OpenOptions::new().write(true).open(body).unwrap();
    f.seek(SeekFrom::Start(16 + 8 * earlier)).unwrap();
    f.write_all(&[0u8; 8]).unwrap();
    drop(f);
    assert!(
        db.input_edges(parent).unwrap().unwrap()[0].parent.is_null(),
        "the parent's one edge now reads as a coinbase edge"
    );
    for _ in 0..2 {
        let e = dispatch(ctx, "getblockstats", vec![json!(height)]).unwrap_err();
        assert_eq!(e["code"], ERR_MISC, "{e}");
        assert!(
            e["message"].as_str().unwrap().starts_with("invariant: "),
            "no txstat is stamped from the broken block either: {e}"
        );
    }
}

fn walk_for(root: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
    for ent in std::fs::read_dir(root).ok()?.flatten() {
        let path = ent.path();
        if path.file_name().is_some_and(|n| n == name) {
            return Some(path);
        }
        if path.is_dir() {
            if let Some(hit) = walk_for(&path, name) {
                return Some(hit);
            }
        }
    }
    None
}

fn bip9_template(ctx: &RpcContext) -> Value {
    dispatch(ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap()
}

/// Mine `n` blocks whose header version is `version` (a miner following the
/// template, or not).
fn mine_versioned(ctx: &RpcContext, hub: &rbitcoin_net::ChainHub, version: i32, n: u32) {
    for _ in 0..n {
        let tip = hub.tip_header().unwrap();
        let mut block = rbitcoin_consensus::mine_regtest_paying(
            hub.tip_hash().unwrap(),
            tip.time + 1,
            tip_count(ctx) as u32 + 1,
            true_spk(),
            vec![],
        );
        block.header.version = bitcoin::block::Version::from_consensus(version);
        rbitcoin_consensus::grind_regtest_pow(&mut block.header);
        let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&block))]).unwrap();
        assert!(r.is_null(), "{r}");
    }
}

/// Core's `testdummy` BIP9 states as a template reports them: DEFINED,
/// STARTED, LOCKED_IN, ACTIVE, and back to STARTED when a reorg takes away
/// the signal that locked it in. A 4-block period with a threshold of 3 walks
/// the same states as regtest's 144 and 108.
#[test]
fn template_versionbits_follow_regtest_testdummy() {
    const TOP: i64 = 0x2000_0000;
    const DUMMY: i64 = 1 << 28;
    let mut params = rbitcoin_consensus::ChainParams::regtest();
    assert_eq!(
        params.testdummy,
        Some(rbitcoin_consensus::Bip9Deployment {
            bit: 28,
            period: 144,
            threshold: 108,
        }),
        "Core regtest DEPLOYMENT_TESTDUMMY"
    );
    params.testdummy = Some(rbitcoin_consensus::Bip9Deployment {
        bit: 28,
        period: 4,
        threshold: 3,
    });
    let (ctx, dir, hub) = ctx_regtest_hub_on(params, 300_000_000);
    let defined = bip9_template(&ctx);
    assert_eq!(defined["version"], TOP, "{defined}");
    assert_eq!(defined["rules"], json!(["csv", "!segwit", "taproot"]));
    assert_eq!(defined["vbavailable"], json!({}));
    assert_eq!(defined["vbrequired"], 0);
    assert_eq!(defined["coinbaseaux"], json!({}));

    dispatch(&ctx, "generate", vec![json!(3)]).unwrap();
    let started = bip9_template(&ctx);
    assert_eq!(started["version"], TOP | DUMMY, "{started}");
    assert_eq!(started["vbavailable"], json!({"testdummy": 28}));
    assert_eq!(started["rules"], json!(["csv", "!segwit", "taproot"]));

    mine_versioned(&ctx, &hub, (TOP | DUMMY) as i32, 2);
    dispatch(&ctx, "generate", vec![json!(2)]).unwrap();
    hub.set_block_version(1337);
    assert_eq!(bip9_template(&ctx)["version"], 1337, "2 of 3 signals stay STARTED");
    hub.set_block_version(0);

    dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    mine_versioned(&ctx, &hub, (TOP | DUMMY) as i32, 3);
    let last_signal = best_hash(&ctx);
    let locked = bip9_template(&ctx);
    assert_eq!(locked["height"], 12);
    assert_eq!(locked["version"], TOP | DUMMY, "{locked}");
    assert_eq!(locked["vbavailable"], json!({"testdummy": 28}));
    assert_eq!(locked["rules"], json!(["csv", "!segwit", "taproot"]));
    hub.set_block_version(1337);
    assert_eq!(bip9_template(&ctx)["version"], 1337 | DUMMY, "LOCKED_IN sets the bit");
    hub.set_block_version(0);

    dispatch(&ctx, "generate", vec![json!(4)]).unwrap();
    let active = bip9_template(&ctx);
    assert_eq!(active["height"], 16);
    assert_eq!(active["version"], TOP, "{active}");
    assert_eq!(active["vbavailable"], json!({}));
    assert_eq!(active["rules"], json!(["csv", "!segwit", "taproot", "testdummy"]));

    dispatch(&ctx, "invalidateblock", vec![last_signal]).unwrap();
    dispatch(&ctx, "generate", vec![json!(5)]).unwrap();
    let reorged = bip9_template(&ctx);
    assert_eq!(reorged["height"], 16);
    assert_eq!(reorged["version"], TOP | DUMMY, "{reorged}");
    assert_eq!(reorged["vbavailable"], json!({"testdummy": 28}));
    assert_eq!(reorged["rules"], json!(["csv", "!segwit", "taproot"]));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Core `fPreSegWit`: before segwit the template drops `!segwit`/`taproot`
/// and the weight limit, and counts legacy sigops. Core 32 keeps the witness
/// commitment. The mature pad is read with segwit at height 103.
#[test]
fn template_before_segwit_uses_legacy_limits() {
    let mut params = rbitcoin_consensus::ChainParams::regtest();
    params.segwit_height_overlay = Some(103);
    let (ctx, dir, hub) = ctx_from_mature_pad_on(params, 300_000_000);
    assert_eq!(hub.tip_height(), Some(101));
    let cb = generated_coinbase_value(&ctx, 1);
    let checksig = spend_generated_coinbase(&ctx, 1, cb - 1_000, ScriptBuf::from_bytes(vec![0xac])).1;
    dispatch(&ctx, "sendrawtransaction", vec![json!(tx_hex(&checksig))]).unwrap();
    let t = bip9_template(&ctx);
    assert_eq!(t["rules"], json!(["csv"]), "{t}");
    assert_eq!(t["sigoplimit"], 20_000);
    assert_eq!(t["sizelimit"], 1_000_000);
    assert!(t.get("weightlimit").is_none(), "{t}");
    assert!(t.get("default_witness_commitment").is_some(), "{t}");
    assert_eq!(t["transactions"][0]["sigops"], 1, "{t}");
    dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let t = bip9_template(&ctx);
    assert_eq!(t["rules"], json!(["csv", "!segwit", "taproot"]), "{t}");
    assert_eq!(t["sigoplimit"], 80_000);
    assert_eq!(t["weightlimit"], 4_000_000);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Core looks a proposal up in its block index before checking it.
#[test]
fn proposal_of_a_known_block_is_a_duplicate() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    dispatch(&ctx, "generate", vec![json!(2)]).unwrap();
    let tip = best_hash(&ctx);
    let raw = dispatch(&ctx, "getblock", vec![tip.clone(), json!(0)]).unwrap();
    let connected: Block =
        deserialize(&rbitcoin_primitives::hex_decode(raw.as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(propose(&ctx, &connected), "duplicate");

    let mut header_only = proposal_on_tip(&ctx, vec![]);
    regrind(&mut header_only);
    let header_hex =
        rbitcoin_primitives::hex_encode(bitcoin::consensus::encode::serialize(&header_only.header));
    dispatch(&ctx, "submitheader", vec![json!(header_hex)]).unwrap();
    assert_eq!(propose(&ctx, &header_only), "duplicate-inconclusive");

    dispatch(&ctx, "invalidateblock", vec![tip.clone()]).unwrap();
    assert_eq!(propose(&ctx, &connected), "duplicate-invalid");

    dispatch(
        &ctx,
        "generatetodescriptor",
        vec![json!(2), json!("raw(52)#qu92mhx7")],
    )
    .unwrap();
    dispatch(&ctx, "reconsiderblock", vec![tip.clone()]).unwrap();
    assert_ne!(best_hash(&ctx), tip, "the heavier branch stays the tip");
    assert_eq!(
        propose(&ctx, &connected),
        "duplicate",
        "a block connected and then reorged off stays scripts-valid"
    );
    let reorged_off = best_hash(&ctx);

    let mut prev = connected.block_hash();
    let mut time = connected.header.time;
    for height in 3..=4 {
        time += 1;
        let block = rbitcoin_consensus::mine_regtest_paying(prev, time, height, true_spk(), vec![]);
        let r = dispatch(&ctx, "submitblock", vec![json!(block_hex(&block))]).unwrap();
        assert!(r.is_null() || r == "inconclusive", "{r}");
        prev = block.block_hash();
    }
    assert_eq!(best_hash(&ctx), json!(prev.to_string()), "the first branch is back");
    let back = connected.block_hash().to_byte_array();
    assert!(
        !ctx.query.was_disconnected(&back),
        "a reconnected block is no longer remembered as reorged off"
    );
    let off = parse_hash32_display(reorged_off.as_str().unwrap()).unwrap();
    assert!(ctx.query.was_disconnected(&off));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A regtest chain at a fixed harder difficulty (`0x200fffff`, about 1 in 16
/// hashes): `generate`, the template, a proposal and `submitblock` all follow
/// the overlay, and the min-difficulty time gap still admits the limit bits.
#[test]
fn rpc_regtest_pow_bits_overlay() {
    const OVERLAY: u32 = 0x200f_ffff;
    const LIMIT: u32 = 0x207f_ffff;
    let mut params = rbitcoin_consensus::ChainParams::regtest();
    params.apply_regtest_pow_bits(OVERLAY).unwrap();
    let (ctx, dir, _hub) = ctx_regtest_hub_on(params, 300_000_000);
    let (_addr, p2wpkh) = p2wpkh_regtest();

    let hashes = dispatch(&ctx, "generate", vec![json!(3)]).unwrap();
    // Block 1 is more than two spacings after the 2011 genesis, so it may use
    // the limit bits. Every later block follows the overlay.
    for (i, hash) in hashes.as_array().unwrap().iter().enumerate() {
        let hdr = dispatch(&ctx, "getblockheader", vec![hash.clone()]).unwrap();
        let want = if i == 0 { LIMIT } else { OVERLAY };
        assert_eq!(hdr["bits"], format!("{want:08x}"), "height {}", i + 1);
    }

    let tmpl = dispatch(&ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    assert_eq!(tmpl["bits"], format!("{OVERLAY:08x}"));
    let target = bitcoin::Target::from_compact(bitcoin::CompactTarget::from_consensus(OVERLAY));
    assert_eq!(tmpl["target"], format!("{target:064x}"));

    // A block at the old trivial bits is no longer the next work.
    let tip: Block = {
        let raw = dispatch(&ctx, "getblock", vec![best_hash(&ctx), json!(0)]).unwrap();
        deserialize(&rbitcoin_primitives::hex_decode(raw.as_str().unwrap()).unwrap()).unwrap()
    };
    let height = tip_count(&ctx) as u32 + 1;
    let easy = rbitcoin_consensus::mine_regtest_paying(
        tip.block_hash(),
        tip.header.time + 1,
        height,
        p2wpkh.clone(),
        vec![],
    );
    assert_eq!(easy.header.bits.to_consensus(), LIMIT);
    assert_eq!(propose(&ctx, &easy), "bad-diffbits");
    let r = dispatch(&ctx, "submitblock", vec![json!(block_hex(&easy))]).unwrap();
    assert_eq!(r, "bad-diffbits");
    assert_eq!(tip_count(&ctx), 3);

    // More than two spacings after its parent a block may use the limit bits.
    let late = rbitcoin_consensus::mine_regtest_paying(
        tip.block_hash(),
        tip.header.time + 2 * 600 + 1,
        height,
        p2wpkh,
        vec![],
    );
    let r = dispatch(&ctx, "submitblock", vec![json!(block_hex(&late))]).unwrap();
    assert!(r.is_null(), "min-difficulty gap block: {r}");
    // The next block is back at the overlay.
    let more = dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let hdr = dispatch(&ctx, "getblockheader", vec![more[0].clone()]).unwrap();
    assert_eq!(hdr["bits"], format!("{OVERLAY:08x}"));
    assert_eq!(tip_count(&ctx), 5);
    let _ = std::fs::remove_dir_all(&dir);
}
