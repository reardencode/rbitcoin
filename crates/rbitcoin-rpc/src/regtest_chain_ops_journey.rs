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
    hex_encode(bitcoin::consensus::encode::serialize(block))
}

fn tx_hex(tx: &Transaction) -> String {
    hex_encode(bitcoin::consensus::encode::serialize(tx))
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
    let mined: Block = deserialize(&hex_decode(raw.as_str().unwrap()).unwrap()).unwrap();
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

/// One regtest hub an operator drives over RPC from genesis: mine, submit,
/// headers, templates, mocktime, fee caps, invalidate and precious.
#[test]
fn rpc_regtest_chain_ops() {
    let (mut ctx, dir, hub) = ctx_regtest_hub();
    let (addr, p2wpkh) = p2wpkh_regtest();
    let store = dir.join("store");
    chain_ops_at_genesis(&ctx, &hub, &store);
    chain_ops_refusals_at_genesis(&ctx, &hub);
    chain_ops_first_block_to_an_address(&ctx, &hub, &addr, &p2wpkh);
    chain_ops_first_block_info(&ctx, &hub, &store, &p2wpkh);
    chain_ops_mocktime(&ctx, &hub, &p2wpkh);
    chain_ops_coinbase_only_blocks(&ctx);
    chain_ops_empty_template_and_proposals(&ctx);
    chain_ops_header_rejects(&ctx, &hub, &p2wpkh);
    chain_ops_submit_rejects(&ctx, &hub, &p2wpkh);

    let mut cbs = TrueCoinbases(tip_count(&ctx) as u32 + 1);
    dispatch(&ctx, "generate", vec![json!(120)]).unwrap();
    chain_ops_mature_pad_work(&ctx);
    chain_ops_template_sigops_and_script_reject(&ctx, &mut cbs);
    chain_ops_sigop_adjusted_entry_and_min_fee(&ctx, &mut cbs);
    chain_ops_submitpackage_sigop_vsize(&ctx, &mut cbs);
    chain_ops_big_sigops_cluster(&ctx, &mut cbs);
    chain_ops_prioritise(&ctx, &mut cbs);
    let fee_block = chain_ops_generateblock_and_parent_first(&ctx, &mut cbs);
    chain_ops_proposal_spends(&ctx, &mut cbs);
    chain_ops_maxfeerate(&ctx, &mut cbs);
    chain_ops_invalidate_and_precious(&ctx, &hub, &mut cbs, &p2wpkh);

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

fn chain_ops_at_genesis(ctx: &RpcContext, hub: &rbitcoin_net::ChainHub, store: &std::path::Path) {
    let info = dispatch(ctx, "getblockchaininfo", vec![]).unwrap();
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
    let e = dispatch(ctx, "submitheader", vec![json!(hex_encode(orphan))]).unwrap_err();
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
        hex_encode(tip.to_byte_array()),
        "display order differs from internal hex"
    );
    assert_eq!(dispatch(ctx, "getblockhash", vec![json!(1)]).unwrap(), best);

    let blk = dispatch(ctx, "getblock", vec![best.clone(), json!(2)]).unwrap();
    let cb_out = &blk["tx"][0]["vout"][0]["scriptPubKey"];
    assert_eq!(cb_out["hex"], hex_encode(p2wpkh.as_bytes()));
    assert_eq!(cb_out["address"], json!(addr));
    // Core getblock(hash, False) is verbosity 0 (raw hex).
    let raw = dispatch(ctx, "getblock", vec![best.clone(), json!(false)]).unwrap();
    assert!(raw.as_str().unwrap().len() > 160);
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
    // Core third arg is a blockhash; we always have Class A — ignore it.
    let same = dispatch(
        ctx,
        "getrawtransaction",
        vec![json!(cb_txid), json!(0), best.clone()],
    )
    .unwrap();
    assert_eq!(same, raw_tx);
    let verbose = dispatch(ctx, "getrawtransaction", vec![json!(cb_txid), json!(true)]).unwrap();
    assert_eq!(verbose["txid"], cb_txid);
    let internal = hex_encode(parse_hash32_display(cb_txid).unwrap());
    assert!(
        dispatch(ctx, "getrawtransaction", vec![json!(internal)]).is_err(),
        "internal-order hex must not resolve as a Core display txid"
    );
    let tma = dispatch(ctx, "testmempoolaccept", vec![json!([raw_tx.clone()])]).unwrap();
    assert_eq!(tma[0]["allowed"], false, "{tma}");
    assert!(dispatch(ctx, "sendrawtransaction", vec![raw_tx]).is_err());
    let net = dispatch(ctx, "getnetworkinfo", vec![]).unwrap();
    assert_eq!(net["connections_in"], 0);

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
    let far = rbitcoin_consensus::mine_regtest_paying(
        hub.tip_hash().unwrap(),
        (mock + 3 * 3600) as u32,
        3,
        p2wpkh.clone(),
        vec![],
    );
    let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&far))]).unwrap();
    assert_eq!(r, "time-too-new", "future header vs mock now");
    dispatch(ctx, "setmocktime", vec![json!(0)]).unwrap();
}

fn chain_ops_coinbase_only_blocks(ctx: &RpcContext) {
    let hashes = dispatch(ctx, "generate", vec![json!(2)]).unwrap();
    let first = hashes[0].clone();
    let tip = hashes[1].clone();
    ctx.query.store().reset_tx_full_gets();
    let v1 = dispatch(ctx, "getblock", vec![first.clone(), json!(1)]).unwrap();
    assert!(
        ctx.query.store().tx_full_gets().is_empty(),
        "verbosity 1 must not zip seqsigwit: {:?}",
        ctx.query.store().tx_full_gets()
    );
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
    assert_eq!(tmpl["version"], 0x2000_0000 | (1 << 28));
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
    assert_eq!(propose(ctx, &bad_cb), "bad-cb-missing");
    let mut empty = next.clone();
    empty.txdata.clear();
    assert_eq!(propose(ctx, &empty), "bad-blk-length");
    let mut bits_bad = next.clone();
    bits_bad.header.bits = bitcoin::CompactTarget::from_consensus(469762303);
    assert_eq!(propose(ctx, &bits_bad), "bad-diffbits");
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
        vec![json!(hex_encode(bitcoin::consensus::encode::serialize(&old_hdr)))],
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
        let hex = hex_encode(bitcoin::consensus::encode::serialize(header));
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
    let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&mine(0)))]).unwrap();
    assert!(r.is_null(), "good submitblock: {r}");
    assert_eq!(tip_count(ctx), before + 1);

    let mut bad = mine(0);
    bad.header.merkle_root = bitcoin::TxMerkleNode::from_byte_array([0xab; 32]);
    regrind(&mut bad);
    let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&bad))]).unwrap();
    assert_eq!(r, "bad-txnmrklroot");

    let mut empty = mine(1);
    empty.txdata.clear();
    let mut no_cb = mine(2);
    no_cb.txdata[0].input[0].previous_output = OutPoint {
        txid: Txid::from_byte_array([0x11; 32]),
        vout: 0,
    };
    let mut dup = mine(3);
    dup.txdata.push(dup.txdata[0].clone());
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
    below.txdata.push(spend(OutPoint { txid: cb, vout: 0 }, u64::MAX));
    let mut miss = mine(5);
    let ghost = OutPoint {
        txid: Txid::from_byte_array([0x22; 32]),
        vout: 0,
    };
    miss.txdata.push(spend(ghost, 1));
    for (block, want) in [
        (empty, "bad-blk-length"),
        (no_cb, "bad-cb-missing"),
        (dup, "bad-txns-duplicate"),
        (below, "bad-txns-in-belowout"),
        (miss, "bad-txns-inputs-missingorspent"),
    ] {
        let r = dispatch(ctx, "submitblock", vec![json!(block_hex(&block))]).unwrap();
        assert_eq!(r, want);
    }
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
        vec![json!({"rules": ["segwit"], "longpollid": "not-this-id"})],
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
    dispatch(ctx, "sendrawtransaction", vec![json!(tx_hex(&tx))]).unwrap();
    let raw_w = tx.weight().to_wu();
    assert!(raw_w < 16_000);
    let e = dispatch(
        ctx,
        "getmempoolentry",
        vec![json!(hash_hex_display(&tid.to_byte_array()))],
    )
    .unwrap();
    assert_eq!(e["vsize"], 4_000);
    assert_eq!(e["weight"], raw_w);
    assert_eq!(e["ancestorsize"], 4_000);
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
        crate::methods::mine::mempool_block_txs(ctx)
            .into_iter()
            .map(|(tx, _)| tx)
            .collect::<Vec<_>>()
    };
    // 2_000 sat is 0.5 sat/vB at 4_000 vB.
    assert_eq!(keep(500), vec![tx.clone()]);
    assert_eq!(keep(501), Vec::<Transaction>::new());
    ctx.mempool.as_ref().unwrap().set_bytes_per_sigop(0);
    assert_eq!(keep(501), vec![tx]);
    chain_ops_restore_sigop_mining_knobs(ctx);
    chain_ops_mine_pool_empty(ctx);
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
    assert_eq!(row(&parent)["vsize"], 4_000, "{r}");
    assert_eq!(row(&child)["vsize"], child.vsize(), "{r}");
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
        let raw = hex_decode(t["data"].as_str().unwrap()).unwrap();
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
    assert_eq!(crate::methods::mine::gbt_check_proposal(ctx, &block), Ok(()));
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

    let scan = dispatch(ctx, "scantxoutset", vec![json!("start"), json!([op_true])]).unwrap();
    let uns = scan["unspents"].as_array().unwrap();
    let cb_hex = parent.input[0].previous_output.txid.to_string();
    assert!(
        uns.iter().all(|u| u["txid"] != json!(cb_hex)),
        "spent coinbase drops from the scan: {scan}"
    );
    assert!(uns.iter().any(|u| u["txid"] == child_id && u["coinbase"] == false));

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
    assert_eq!(
        propose(ctx, &proposal_on_tip(ctx, vec![spend.clone(), spend.clone()])),
        "bad-txns-inputs-missingorspent",
        "a second copy spends the same coin"
    );
    let mut fat = spend.clone();
    fat.output[0].value = Amount::from_sat(cb_f + 1);
    assert_eq!(
        propose(ctx, &proposal_on_tip(ctx, vec![fat])),
        "bad-txns-in-belowout"
    );
    let mut locked = spend.clone();
    locked.lock_time = LockTime::from_height(tip_count(ctx) as u32 + 50).unwrap();
    locked.input[0].sequence = bitcoin::Sequence::ZERO;
    assert_eq!(
        propose(ctx, &proposal_on_tip(ctx, vec![locked])),
        "bad-txns-nonfinal"
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
        propose(ctx, &proposal_on_tip(ctx, vec![spend])),
        "bad-txns-inputs-missingorspent",
        "a coin a block spent is gone from the proposal view"
    );
}

fn chain_ops_maxfeerate(ctx: &RpcContext, cbs: &mut TrueCoinbases) {
    let heights: Vec<u32> = (0..6).map(|_| cbs.take()).collect();
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
    let over = dispatch(ctx, "sendrawtransaction", vec![json!(hex), json!(100_000)]).unwrap_err();
    assert_eq!(over["code"], ERR_INVALID_PARAMETER, "{over}");
    assert_eq!(over["message"], "feerate >= 100000 sat/vB is not accepted");

    let modest_at = |h: u32| {
        spend_generated_coinbase(ctx, h, generated_coinbase_value(ctx, h) - 1_000, true_spk())
    };
    let (modest_hex, modest) = modest_at(heights[3]);
    let ok99 = dispatch(ctx, "sendrawtransaction", vec![json!(modest_hex), json!(99_999)]).unwrap();
    assert_eq!(ok99, json!(modest.compute_txid().to_string()));
    pin_maxfeerate_json_shapes(ctx);
    let (str_hex, str_tx) = modest_at(heights[4]);
    let ok_str = dispatch(ctx, "sendrawtransaction", vec![json!(str_hex), json!("99999")]).unwrap();
    assert_eq!(ok_str, json!(str_tx.compute_txid().to_string()));

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
    let archived = tma(&hex);
    assert_eq!(archived["allowed"], true, "{archived}");
    dispatch(ctx, "reconsiderblock", vec![tip.clone()]).unwrap();
    assert_eq!(tip_count(ctx), tip_h);
    assert_eq!(best_hash(ctx), tip);

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
