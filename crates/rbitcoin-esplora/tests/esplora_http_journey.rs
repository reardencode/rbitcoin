struct HttpPad {
    q: Arc<Query>,
    hub: Arc<rbitcoin_net::MempoolHub>,
    addr: SocketAddr,
    /// Coinbase txids by height.
    cbs: Vec<[u8; 32]>,
    hashes: Vec<[u8; 32]>,
    tip_fk: Fk,
}

impl HttpPad {
    fn tip(&self) -> u32 {
        u32::try_from(self.hashes.len() - 1).unwrap()
    }

    fn connect(&mut self, extra: Vec<TxApply>) {
        let h = u32::try_from(self.hashes.len()).unwrap();
        let (header, cb) = coinbase(h, self.tip_fk, self.hashes.last().copied());
        let mut txs = vec![cb];
        txs.extend(extra);
        self.cbs.push(txs[0].tx.txid);
        self.hashes.push(header.hash);
        self.tip_fk = self.q.connect_block(Height(h), &header, &txs).unwrap();
    }
}

fn pay_txid(tag: u8) -> [u8; 32] {
    two_script_pay(tag, bitcoin::ScriptBuf::new()).tx.txid
}

async fn empty_chain_has_no_tip(addr: SocketAddr) {
    let (st, raw, _) = http_get_raw(addr, "/blocks/tip/height").await;
    assert_eq!(st, 503);
    assert!(
        header_value(&raw, HDR_CHAIN_TIP).is_none(),
        "empty chain must omit the tip header"
    );
    let (st, _) = http_get(addr, "/blocks/tip/hash").await;
    assert_eq!(st, 503);
}

async fn tip_headers_and_powered_by(pad: &HttpPad) {
    let (st, raw, body) = http_get_raw(pad.addr, "/blocks/tip/hash").await;
    assert_eq!(st, 200, "hash body={body}");
    let tip = header_value(&raw, HDR_CHAIN_TIP).expect("X-Bitcoin-Chain-Tip");
    let height = header_value(&raw, HDR_CHAIN_TIP_HEIGHT).expect("height");
    assert_eq!(tip, body);
    assert_eq!(tip, block_hash_hex(pad.hashes.last().unwrap()));
    assert_eq!(height, pad.tip().to_string());
    let expose = header_value(&raw, "access-control-expose-headers").unwrap_or_default();
    assert!(
        expose.to_ascii_lowercase().contains("x-bitcoin-chain-tip"),
        "CORS must expose the tip header: {expose}"
    );

    let (st, raw, body) = http_get_raw(pad.addr, "/blocks/tip/height").await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body, pad.tip().to_string());
    assert_eq!(
        header_value(&raw, HDR_CHAIN_TIP).as_deref(),
        Some(tip.as_str())
    );
    let powered = header_value(&raw, "x-powered-by").expect("X-Powered-By");
    assert!(
        powered.starts_with("rbitcoin-esplora/"),
        "prefix: {powered}"
    );
    let hex_run = powered
        .bytes()
        .collect::<Vec<_>>()
        .windows(5)
        .any(|w| w.iter().all(|b| b.is_ascii_hexdigit()));
    assert!(hex_run, "need ≥5 hex for mempool failover: {powered}");

    let (st, body) = http_get(pad.addr, "/no/such/path").await;
    assert_eq!(st, 404, "404 body={body}");
    assert!(body.to_ascii_lowercase().contains("not found") || body.contains("Not Found"));
}

/// `sh1` got t1 then t3; `sh2` got t2 in between.
async fn wallet_pages_after_txid(addr: SocketAddr, sh1: &str) {
    let [t1, t3] = [0x11, 0x33].map(|tag| block_hash_hex(&pay_txid(tag)));
    let (st, body) = http_get(addr, &format!("/scripthash/{sh1}/txs")).await;
    assert_eq!(st, 200, "{body}");
    let all: Vec<Value> = serde_json::from_str(&body).unwrap();
    let ids: Vec<&str> = all.iter().filter_map(|v| v["txid"].as_str()).collect();
    assert_eq!(ids, vec![t3.as_str(), t1.as_str()]);
    let (st, body) = http_get(addr, &format!("/scripthash/{sh1}/txs?after_txid={t3}")).await;
    assert_eq!(st, 200, "{body}");
    let page: Vec<Value> = serde_json::from_str(&body).unwrap();
    let ids: Vec<&str> = page.iter().filter_map(|v| v["txid"].as_str()).collect();
    assert_eq!(ids, vec![t1.as_str()]);
    let (st, body) = http_get(
        addr,
        &format!("/scripthash/{sh1}/txs/summary?after_txid={t3}"),
    )
    .await;
    assert_eq!(st, 200, "{body}");
    let sum: Vec<Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(sum[0]["txid"], t1);
    assert_eq!(sum[0]["tx_position"], 1, "pay sits after the coinbase: {sum:?}");
    assert!(!sum.iter().any(|v| v["txid"] == t3));

    let unknown = "ff".repeat(32);
    for path in [
        format!("/scripthash/{sh1}/txs?after_txid={unknown}"),
        format!("/scripthash/{sh1}/txs/summary?after_txid={unknown}"),
    ] {
        let (st, body) = http_get(addr, &path).await;
        assert_eq!(st, 422, "{path}: {body}");
        assert!(body.contains("after_txid not found"), "{body}");
    }
    let (st, body) = http_get(addr, &format!("/scripthash/{sh1}/txs?after_txid=zz")).await;
    assert_eq!(st, 422, "{body}");
    let (st, body) = http_get(addr, &format!("/scripthash/{sh1}/txs/chain/{t3}")).await;
    assert_eq!(st, 200, "{body}");
    let page: Vec<Value> = serde_json::from_str(&body).unwrap();
    let ids: Vec<&str> = page.iter().filter_map(|v| v["txid"].as_str()).collect();
    assert_eq!(ids, vec![t1.as_str()]);

    foreign_chain_cursor_is_not_this_page(addr, sh1, &t1, &t3).await;
}

/// Combined `/txs` with a confirmed cursor is the chain page: the mempool tx
/// stays off the body. A mempool cursor keeps only the mempool tail, then
/// that same confirmed page. An unknown cursor stays 422.
async fn chain_cursor_matches_chain_page(pad: &HttpPad, mempool_tx: &bitcoin::Transaction) {
    let sh = block_hash_hex(&script_hash(&[0x51]));
    let mem_hex = display_txid(mempool_tx.compute_txid());
    let confirmed = block_hash_hex(pad.cbs.last().expect("tip coinbase"));

    let (st, chain) = http_get(
        pad.addr,
        &format!("/scripthash/{sh}/txs/chain/{confirmed}"),
    )
    .await;
    assert_eq!(st, 200, "{chain}");
    let (st, combined) = http_get(
        pad.addr,
        &format!("/scripthash/{sh}/txs?after_txid={confirmed}"),
    )
    .await;
    assert_eq!(st, 200, "{combined}");
    assert_eq!(combined, chain, "confirmed cursor is the chain page");
    assert!(
        !combined.contains(&mem_hex),
        "mempool tx on a confirmed cursor: {combined}"
    );

    let (st, first_chain) = http_get(pad.addr, &format!("/scripthash/{sh}/txs/chain")).await;
    assert_eq!(st, 200, "{first_chain}");
    let (st, after_mem) = http_get(
        pad.addr,
        &format!("/scripthash/{sh}/txs?after_txid={mem_hex}"),
    )
    .await;
    assert_eq!(st, 200, "{after_mem}");
    assert_eq!(
        after_mem, first_chain,
        "one mempool tx leaves an empty tail, then the confirmed page"
    );
    assert!(!after_mem.contains(&mem_hex), "{after_mem}");

    let unknown = "ff".repeat(32);
    let (st, body) = http_get(
        pad.addr,
        &format!("/scripthash/{sh}/txs?after_txid={unknown}"),
    )
    .await;
    assert_eq!(st, 422, "{body}");
    assert!(body.contains("after_txid not found"), "{body}");
}

async fn foreign_chain_cursor_is_not_this_page(addr: SocketAddr, sh1: &str, t1: &str, t3: &str) {
    let t2 = block_hash_hex(&pay_txid(0x22));
    for path in [
        format!("/scripthash/{sh1}/txs?after_txid={t2}"),
        format!("/scripthash/{sh1}/txs/summary?after_txid={t2}"),
        format!("/scripthash/{sh1}/txs/chain/{t2}"),
    ] {
        let (st, body) = http_get(addr, &path).await;
        assert_eq!(st, 422, "{path}: {body}");
        assert!(body.contains("after_txid not found"), "{body}");
        assert!(!body.contains(t1) && !body.contains(t3), "{path}: {body}");
    }
}

async fn wallet_posts_scripthashes(addr: SocketAddr, a: [&str; 2], sh: [&str; 2]) {
    let [t1, t2, t3] = [0x11, 0x22, 0x33].map(|tag| block_hash_hex(&pay_txid(tag)));
    let unknown = "ff".repeat(32);
    let body = serde_json::to_vec(&json!(sh)).unwrap();
    let (st, resp) = http_post(addr, "/scripthashes/txs", &body).await;
    assert_eq!(st, 200, "{resp}");
    let rows: Vec<Value> = serde_json::from_str(&resp).unwrap();
    let ids: Vec<&str> = rows.iter().filter_map(|v| v["txid"].as_str()).collect();
    assert_eq!(ids, vec![t3.as_str(), t2.as_str(), t1.as_str()], "{resp}");
    let (st, resp) = http_post(
        addr,
        "/addresses/txs",
        &serde_json::to_vec(&json!(a)).unwrap(),
    )
    .await;
    assert_eq!(st, 200, "{resp}");
    let rows: Vec<Value> = serde_json::from_str(&resp).unwrap();
    assert_eq!(rows[0]["txid"], t3);
    let (st, resp) = http_post(addr, "/scripthashes/txs/summary", &body).await;
    assert_eq!(st, 200, "{resp}");
    let rows: Vec<Value> = serde_json::from_str(&resp).unwrap();
    assert_eq!(rows[0]["txid"], t3);
    assert_eq!(rows[1]["txid"], t2);
    let (st, resp) = http_post(addr, &format!("/scripthashes/txs?after_txid={t3}"), &body).await;
    assert_eq!(st, 200, "{resp}");
    let rows: Vec<Value> = serde_json::from_str(&resp).unwrap();
    assert_eq!(rows[0]["txid"], t2);
    assert!(!rows.iter().any(|v| v["txid"] == t3));
    let (st, resp) = http_post(
        addr,
        &format!("/scripthashes/txs?after_txid={unknown}"),
        &body,
    )
    .await;
    assert_eq!(st, 422, "{resp}");
    assert!(resp.contains("after_txid not found"), "{resp}");
    cursor_outside_one_script_is_422(addr, a[0], sh[0], &t1, &t2, &t3).await;
    let too: Vec<String> = (0..301).map(|_| "aa".repeat(32)).collect();
    let (st, resp) = http_post(
        addr,
        "/scripthashes/txs",
        &serde_json::to_vec(&too).unwrap(),
    )
    .await;
    assert_eq!(st, 422, "{resp}");
    assert!(resp.contains("body too long"), "{resp}");
}

async fn cursor_outside_one_script_is_422(
    addr: SocketAddr,
    address: &str,
    sh: &str,
    t1: &str,
    t2: &str,
    t3: &str,
) {
    let only = serde_json::to_vec(&json!([sh])).unwrap();
    let (st, resp) = http_post(addr, &format!("/scripthashes/txs?after_txid={t2}"), &only).await;
    assert_eq!(st, 422, "{resp}");
    assert!(resp.contains("after_txid not found"), "{resp}");
    assert!(!resp.contains(t1) && !resp.contains(t3), "{resp}");
    let (st, resp) = http_get(addr, &format!("/address/{address}/txs?after_txid={t2}")).await;
    assert_eq!(st, 422, "{resp}");
    assert!(resp.contains("after_txid not found"), "{resp}");
}

/// Packed SH `/txs` runs on `spawn_blocking`, so tip height still answers on
/// the test's single worker.
async fn tip_height_overlaps_scripthash_txs(pad: &HttpPad) {
    let addr = pad.addr;
    let t0 = Instant::now();
    let txs_path = format!("/scripthash/{}/txs", block_hash_hex(&script_hash(&[0x51])));
    let h_txs = tokio::spawn(async move { http_get(addr, &txs_path).await });
    let h_tip = tokio::spawn(async move { http_get(addr, "/blocks/tip/height").await });
    let (txs, tip) = tokio::join!(h_txs, h_tip);
    let (st_txs, _) = txs.unwrap();
    let (st_tip, body_tip) = tip.unwrap();
    assert_eq!(st_txs, 200);
    assert_eq!(st_tip, 200, "{body_tip}");
    assert_eq!(body_tip, pad.tip().to_string());
    assert!(t0.elapsed().as_secs() < 2);
}

/// A mempool-only spend is full Esplora JSON (not a stub) on every route.
async fn mempool_spend_is_full_json(pad: &HttpPad) -> bitcoin::Transaction {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize_hex;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

    let addr = pad.addr;
    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array(pad.cbs[0]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let (st, body) = http_post(addr, "/tx", serialize_hex(&spend).as_bytes()).await;
    assert_eq!(st, 200, "POST /tx: {body}");
    let txid_hex = display_txid(spend.compute_txid());
    assert_eq!(body, txid_hex);
    assert!(pad.hub.contains(&spend.compute_txid()));
    assert!(
        pad.hub.is_local_origin(&spend.compute_txid()),
        "POST /tx is a local submit"
    );
    let sh_hex = block_hash_hex(&script_hash(&[0x51]));

    let (st, body) = http_get(addr, &format!("/scripthash/{sh_hex}/txs/mempool")).await;
    assert_eq!(st, 200, "{body}");
    let arr: Value = serde_json::from_str(&body).unwrap();
    let row = arr
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["txid"] == txid_hex)
        .expect("mempool list contains spend");
    for key in ["vin", "vout", "size", "weight"] {
        assert!(row.get(key).is_some(), "stub omitted {key}: {row}");
    }
    assert_eq!(row["status"]["confirmed"], false);
    assert_eq!(row["fee"], 1_000);

    let (st, body) = http_get(addr, &format!("/scripthash/{sh_hex}/txs")).await;
    assert_eq!(st, 200, "{body}");
    let arr: Value = serde_json::from_str(&body).unwrap();
    let row = arr
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["txid"] == txid_hex)
        .expect("combined /txs contains spend");
    assert!(row.get("vin").is_some(), "combined stub omitted vin: {row}");

    let (st, body) = http_get(addr, &format!("/tx/{txid_hex}")).await;
    assert_eq!(st, 200, "GET /tx mempool-only: {body}");
    let full: Value = serde_json::from_str(&body).unwrap();
    for key in ["vin", "vout", "size", "weight"] {
        assert!(full.get(key).is_some(), "GET /tx omitted {key}: {full}");
    }
    assert_eq!(full["status"]["confirmed"], false);
    let (st, body) = http_get(addr, &format!("/tx/{txid_hex}/status")).await;
    assert_eq!(st, 200, "GET /tx status mempool-only: {body}");
    let status: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(status["confirmed"], false);

    spend
}

/// The spent coinbase shows the mempool spend; `?asof=` hides it.
async fn mempool_spend_outspends_and_hex(pad: &HttpPad, spend: &bitcoin::Transaction) {
    use bitcoin::consensus::encode::serialize_hex;

    let addr = pad.addr;
    let txid_hex = display_txid(spend.compute_txid());
    let cb0 = block_hash_hex(&pad.cbs[0]);
    let (st, body) = http_get(addr, &format!("/tx/{cb0}/outspend/0")).await;
    assert_eq!(st, 200, "mempool-spent confirmed coin: {body}");
    let os: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(os["spent"], true, "{os}");
    assert_eq!(os["txid"], txid_hex);
    assert_eq!(os["status"]["confirmed"], false);
    let (st, body) = http_get(addr, &format!("/tx/{txid_hex}/outspend/0")).await;
    assert_eq!(st, 200, "mempool-only create outspend: {body}");
    let os: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(os["spent"], false, "{os}");
    let asof0 = block_hash_hex(&pad.hashes[0]);
    let (st, body) = http_get(addr, &format!("/tx/{cb0}/outspend/0?asof={asof0}")).await;
    assert_eq!(st, 200, "asof outspend: {body}");
    let os: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(os["spent"], false, "asof omits mempool spend: {os}");

    let (st, hex_body) = http_get(addr, &format!("/tx/{txid_hex}/hex")).await;
    assert_eq!(st, 200, "{hex_body}");
    assert_eq!(hex_body, serialize_hex(spend));
    let (st, _) = http_get(addr, &format!("/tx/{txid_hex}/raw")).await;
    assert_eq!(st, 200);
}

async fn junk_paths_asof_and_post(addr: SocketAddr, genesis: &[u8; 32]) {
    let h0hex = block_hash_hex(genesis);
    for (path, want) in [
        ("/block/zz".to_string(), 404),
        ("/tx/aa".into(), 404),
        ("/scripthash/aa".into(), 404),
        ("/block-height/nope".into(), 400),
        ("/address/not-an-address".into(), 404),
        (format!("/tx/{h0hex}/outspend/nope"), 400),
        ("/blocks/nope".into(), 400),
        (format!("/tx/{h0hex}?asof={h0hex}"), 404),
        (format!("/mempool?asof={h0hex}"), 404),
        (format!("/tx/{h0hex}/status?asof=zz"), 404),
        (format!("/tx/{h0hex}/status?asof="), 404),
        ("/tx/aa/status?asof=nothex".into(), 404),
        ("/tx".into(), 405),
    ] {
        let (st, body) = http_get(addr, &path).await;
        assert_eq!(st, want, "{path}: {body}");
    }

    for (path, body, want) in [
        ("/tx", &b"zz"[..], Some("invalid hex")),
        ("/tx", b"", None),
        ("/txs/package", b"{}", Some("JSON array")),
        ("/txs/package", b"not-json", Some("invalid json")),
        ("/txs/package", b"[1]", Some("hex string")),
    ] {
        let (st, resp) = http_post(addr, path, body).await;
        assert_eq!(st, 400, "{path}: {resp}");
        if let Some(needle) = want {
            assert!(resp.contains(needle), "{path}: {resp}");
        }
    }

    let sh = block_hash_hex(&script_hash(&[0x51]));
    let (st, body) = http_get(
        addr,
        &format!("/scripthash/{sh}/txs/summary?asof={h0hex}"),
    )
    .await;
    assert_eq!(st, 200, "summary accepts ?asof=: {body}");
    let rows: Vec<Value> = serde_json::from_str(&body).unwrap();
    assert!(
        rows.iter().any(|r| r["tx_position"] == 0),
        "genesis coinbase is position 0: {body}"
    );
}

/// A same-height replace restamps a scripthash read. `/mempool` never pins a view.
async fn tip_coinbase_output(pad: &HttpPad) -> (String, Value, String) {
    let h = pad.tip();
    let out_path = format!("/block-height/{h}/tx/0/out/0");
    let (st, body) = http_get(pad.addr, &out_path).await;
    assert_eq!(st, 200, "tip coinbase output: {body}");
    let out: Value = serde_json::from_str(&body).unwrap();
    let missing = format!("/block-height/{h}/tx/1/out/0");
    let (st, gap) = http_get(pad.addr, &missing).await;
    assert_eq!(st, 404, "coinbase-only block has no index 1: {gap}");
    (out_path, out, missing)
}

async fn same_height_replace_restamps(pad: &mut HttpPad) {
    let (out_path, before, missing) = tip_coinbase_output(pad).await;
    let old_hash = block_hash_hex(pad.hashes.last().unwrap());
    assert_eq!(before["status"]["block_hash"], old_hash, "{before}");
    assert_eq!(before["scriptpubkey"], "51", "{before}");

    let sh_hex = block_hash_hex(&script_hash(&[0x51]));
    let path = format!("/scripthash/{sh_hex}/utxo");
    let (st, raw_a, _) = http_get_raw(pad.addr, &path).await;
    assert_eq!(st, 200, "utxo A");
    let tip_a = header_value(&raw_a, HDR_CHAIN_TIP).expect("tip A");
    assert_eq!(tip_a, block_hash_hex(pad.hashes.last().unwrap()));

    pad.q.disconnect_tip().unwrap();
    let h = pad.tip();
    pad.hashes.pop();
    pad.cbs.pop();
    let parent = *pad.hashes.last().unwrap();
    let prev_fk = pad.q.tip_header_fk().unwrap().unwrap();
    let (mut hb, tb) = coinbase(h, prev_fk, Some(parent));
    hb.nonce = hb.nonce.wrapping_add(1);
    hb.hash = rbitcoin_store::block_header_hash(
        hb.version,
        &parent,
        &hb.merkle_root,
        hb.timestamp,
        hb.bits,
        hb.nonce,
    );
    pad.cbs.push(tb.tx.txid);
    pad.hashes.push(hb.hash);
    pad.tip_fk = pad.q.connect_block(Height(h), &hb, &[tb]).unwrap();

    let (st, raw_b, _) = http_get_raw(pad.addr, &path).await;
    assert_eq!(st, 200, "utxo B");
    let tip_b = header_value(&raw_b, HDR_CHAIN_TIP).expect("tip B");
    assert_eq!(tip_b, block_hash_hex(&hb.hash));
    assert_ne!(tip_a, tip_b);

    let (st, body) = http_get(pad.addr, &out_path).await;
    assert_eq!(st, 200, "replaced tip still has index 0: {body}");
    let after: Value = serde_json::from_str(&body).unwrap();
    let new_hash = block_hash_hex(&hb.hash);
    assert_eq!(after["status"]["block_hash"], new_hash, "{after}");
    assert_ne!(after["status"]["block_hash"], old_hash);
    assert_eq!(after["scriptpubkey"], before["scriptpubkey"], "{after}");
    assert_eq!(after["value"], before["value"], "{after}");
    assert_eq!(after["spent"], false, "{after}");
    let (st, body) = http_get(pad.addr, &missing).await;
    assert_eq!(st, 404, "replaced block still has no index 1: {body}");

    let (st, raw, body) = http_get_raw(pad.addr, "/mempool").await;
    assert_eq!(
        st, 200,
        "mempool must not 503 on same-height replace: {body}"
    );
    assert!(
        header_value(&raw, HDR_CHAIN_TIP).is_none(),
        "mempool must not pin/stamp a chain view"
    );
}

/// Once the tip is past the prune window, old tx JSON is partial and raw is 404.
async fn pruned_tail_is_partial_json(pad: &mut HttpPad) {
    while pad.hashes.len() < 300 {
        pad.connect(vec![]);
    }
    pad.q.set_prune_seqsigwit(true).unwrap();
    pad.q.apply_prune_seqsigwit_tip().unwrap();

    let tx0 = block_hash_hex(&pad.cbs[0]);
    let (st, body) = http_get(pad.addr, &format!("/tx/{tx0}")).await;
    assert_eq!(st, 200, "{body}");
    let (st, by_pos) = http_get(pad.addr, "/block-height/0/tx/0").await;
    assert_eq!(st, 200, "pruned position tx: {by_pos}");
    assert_eq!(by_pos, body, "pruned position tx matches GET /tx");
    let row: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(row["txid"], tx0);
    assert_eq!(row["pruned"], true);
    assert_eq!(row["vin"][0]["is_coinbase"], true, "{row}");
    assert!(row["vin"][0].get("witness").is_none(), "{row}");
    assert!(row.get("vout").is_some());

    let (st, body) = http_get(pad.addr, &format!("/tx/{tx0}/raw")).await;
    assert_eq!(st, 404, "{body}");
    assert!(body.contains("pruned"), "{body}");

    let h0 = block_hash_hex(&pad.hashes[0]);
    let (st, body) = http_get(pad.addr, &format!("/block/{h0}/txs")).await;
    assert_eq!(st, 200, "{body}");
    let arr: Value = serde_json::from_str(&body).unwrap();
    assert!(
        arr.as_array()
            .unwrap()
            .iter()
            .any(|t| t["txid"] == tx0 && t["pruned"] == true),
        "{body}"
    );
}

/// A mempool-only cursor past the first 50 index rows is not a chain cursor.
/// The confirmed page comes back, without that mempool tx.
#[tokio::test(flavor = "current_thread")]
async fn mempool_cursor_past_the_page_is_the_confirmed_page() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize_hex;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

    let (dir, q) = temp_query("mempool-past-page");
    let q = Arc::new(q);
    let mp_dir = dir.join("mp");
    std::fs::create_dir_all(&mp_dir).unwrap();
    let hub = rbitcoin_net::MempoolHub::open(&mp_dir, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
    let handle = run_esplora(cfg, Arc::clone(&q), Some(Arc::clone(&hub)))
        .await
        .expect("listen");
    let mut pad = HttpPad {
        q,
        hub,
        addr: handle.local_addr,
        cbs: Vec::new(),
        hashes: Vec::new(),
        tip_fk: Fk::NULL,
    };
    for _ in 0..152u32 {
        pad.connect(Vec::new());
    }
    let sh = block_hash_hex(&script_hash(&[0x51]));
    let mut admitted = Vec::new();
    for i in 0..51u32 {
        let tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array(pad.cbs[i as usize]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000 - 2_000 - u64::from(i)),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let (st, body) = http_post(pad.addr, "/tx", serialize_hex(&tx).as_bytes()).await;
        assert_eq!(st, 200, "POST /tx {i}: {body}");
        admitted.push(tx.compute_txid().to_byte_array());
    }
    admitted.sort_unstable();
    let past = block_hash_hex(admitted.last().unwrap());
    let (st, chain) = http_get(pad.addr, &format!("/scripthash/{sh}/txs/chain")).await;
    assert_eq!(st, 200, "{chain}");
    let (st, combined) =
        http_get(pad.addr, &format!("/scripthash/{sh}/txs?after_txid={past}")).await;
    assert_eq!(st, 200, "{combined}");
    assert_eq!(
        combined, chain,
        "a mempool cursor past the page is the confirmed page"
    );
    let body = serde_json::to_vec(&json!([sh])).unwrap();
    let (st, posted) = http_post(
        pad.addr,
        &format!("/scripthashes/txs?after_txid={past}"),
        &body,
    )
    .await;
    assert_eq!(st, 200, "{posted}");
    assert!(!posted.contains(&past), "{posted}");
    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Position and outpoint output objects. Genesis and a mempool-only tx are
/// absent. A mempool spend of a confirmed coin leaves `spent: false`.
async fn confirmed_output_by_position(pad: &HttpPad) {
    let addr = pad.addr;
    let (st, body) = http_get(addr, "/block-height/2/tx/0/out/0").await;
    assert_eq!(st, 200, "unspent coinbase output: {body}");
    let out: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(out["spent"], false, "{out}");
    assert_eq!(out["value"], json!(50_0000_0000u64), "{out}");
    assert_eq!(out["scriptpubkey"], "51", "{out}");
    assert!(out.get("scriptpubkey_address").is_none(), "{out}");
    assert_eq!(out["status"]["confirmed"], true, "{out}");
    assert_eq!(out["status"]["block_height"], 2, "{out}");
    let cb2 = block_hash_hex(&pad.cbs[2]);
    let (st, by_txid) = http_get(addr, &format!("/tx/{cb2}/out/0")).await;
    assert_eq!(st, 200, "{by_txid}");
    assert_eq!(by_txid, body, "outpoint route matches the position route");
    output_misses_are_absent(addr, &block_hash_hex(&pad.cbs[0]), &cb2).await;
    mempool_spend_stays_unspent(pad).await;
}

async fn output_misses_are_absent(addr: SocketAddr, genesis: &str, cb2: &str) {
    let (st, body) = http_get(addr, "/block-height/0/tx/0/out/0").await;
    assert_eq!(st, 404, "genesis coinbase by position: {body}");
    let (st, body) = http_get(addr, &format!("/tx/{genesis}/out/0")).await;
    assert_eq!(st, 404, "genesis coinbase by txid: {body}");

    let (st, body) = http_get(addr, "/block-height/1/tx/2/out/0").await;
    assert_eq!(st, 404, "index past the block: {body}");
    let (st, body) = http_get(addr, "/block-height/2/tx/0/out/1").await;
    assert_eq!(st, 404, "vout past the tx: {body}");
    let (st, body) = http_get(addr, "/block-height/99999/tx/0/out/0").await;
    assert_eq!(st, 404, "height past the tip: {body}");

    let (st, body) = http_get(addr, "/block-height/2/tx/nope/out/0").await;
    assert_eq!(st, 400, "non-integer index: {body}");
    let (st, body) = http_get(addr, &format!("/tx/{cb2}/out/nope")).await;
    assert_eq!(st, 400, "non-integer vout: {body}");
}

async fn mempool_spend_stays_unspent(pad: &HttpPad) {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize_hex;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

    let addr = pad.addr;
    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array(pad.cbs[1]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let (st, body) = http_post(addr, "/tx", serialize_hex(&spend).as_bytes()).await;
    assert_eq!(st, 200, "POST spend of height-1 coinbase: {body}");
    let (st, body) = http_get(addr, "/block-height/1/tx/0/out/0").await;
    assert_eq!(st, 200, "mempool spend stays an output: {body}");
    let out: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(out["spent"], false, "mempool spend must not flip spent: {out}");
    assert_eq!(out["scriptpubkey"], "51", "{out}");
    assert_eq!(out["value"], json!(50_0000_0000u64), "{out}");
    let spend_hex = display_txid(spend.compute_txid());
    let (st, body) = http_get(addr, &format!("/tx/{spend_hex}/out/0")).await;
    assert_eq!(st, 404, "mempool-only tx has no output object: {body}");
}

/// Whole tx at a block position matches `GET /tx/{txid}` with no asof.
/// Genesis is returned here; the output routes 404 it.
async fn tx_by_position_matches_get_tx(pad: &HttpPad) {
    let pay = block_hash_hex(&pay_txid(0x11));
    let (st, by_id) = http_get(pad.addr, &format!("/tx/{pay}")).await;
    assert_eq!(st, 200, "{by_id}");
    let (st, by_pos) = http_get(pad.addr, "/block-height/1/tx/1").await;
    assert_eq!(st, 200, "position tx: {by_pos}");
    assert_eq!(by_pos, by_id, "position tx matches GET /tx");

    let (st, body) = http_get(pad.addr, "/block-height/1/tx/2").await;
    assert_eq!(st, 404, "index past the block: {body}");
    let (st, body) = http_get(pad.addr, "/block-height/99999/tx/0").await;
    assert_eq!(st, 404, "height past the tip: {body}");
    let (st, body) = http_get(pad.addr, "/block-height/1/tx/nope").await;
    assert_eq!(st, 400, "non-integer index: {body}");

    let genesis = block_hash_hex(&pad.cbs[0]);
    let (st, by_id) = http_get(pad.addr, &format!("/tx/{genesis}")).await;
    assert_eq!(st, 200, "{by_id}");
    let (st, by_pos) = http_get(pad.addr, "/block-height/0/tx/0").await;
    assert_eq!(st, 200, "genesis full tx by position: {by_pos}");
    assert_eq!(by_pos, by_id, "genesis position matches GET /tx");
}

/// Batch keeps order, repeats duplicates, and rejects a bad element or a long body.
async fn batch_outputs_keep_order(pad: &HttpPad) {
    let addr = pad.addr;
    let (st, body) = http_post(addr, "/block-heights/txs/outs", b"[]").await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body, "[]");

    let mix = serde_json::to_vec(&json!([[4, 0, 0], [4, 0, 0], [4, 9, 0], [999, 0, 0]])).unwrap();
    let (st, body) = http_post(addr, "/block-heights/txs/outs", &mix).await;
    assert_eq!(st, 200, "{body}");
    let rows: Vec<Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(rows.len(), 4, "{body}");
    assert_eq!(rows[0]["spent"], false, "unspent coinbase: {body}");
    assert_eq!(rows[0]["scriptpubkey"], "51", "{body}");
    assert_eq!(rows[0]["value"], json!(50_0000_0000u64), "{body}");
    assert_eq!(rows[1], rows[0], "duplicate slot repeats: {body}");
    assert!(rows[2].is_null(), "missing index: {body}");
    assert!(rows[3].is_null(), "missing height: {body}");

    let (st, body) = http_post(addr, "/block-heights/txs/outs", b"{\"no\":1}").await;
    assert_eq!(st, 400, "{body}");
    let (st, body) = http_post(addr, "/block-heights/txs/outs", b"[[1,2]]").await;
    assert_eq!(st, 400, "{body}");
    let (st, body) = http_post(addr, "/block-heights/txs/outs", b"[[1,2,\"x\"]]").await;
    assert_eq!(st, 400, "{body}");
    assert!(!body.contains("scriptpubkey"), "400 must not return a partial array: {body}");

    let mut long = Vec::new();
    for _ in 0..301 {
        long.push(json!([2, 0, 0]));
    }
    let raw = serde_json::to_vec(&Value::Array(long)).unwrap();
    let (st, body) = http_post(addr, "/block-heights/txs/outs", &raw).await;
    assert_eq!(st, 422, "{body}");
    assert!(body.contains("body too long"), "{body}");
}

/// One TCP Esplora on one hub: an empty chain, then a mature pad a wallet
/// pages, a mempool spend, junk requests, a same-height tip replace, and a
/// pruned tail once the chain grows past the prune window.
#[tokio::test(flavor = "current_thread")]
async fn esplora_tcp_wallet_mempool_and_replace() {
    let (a1, spk1) = regtest_p2wpkh();
    let (a2, spk2) = regtest_p2wpkh_sk(9);
    let sh1 = block_hash_hex(&script_hash(spk1.as_bytes()));
    let sh2 = block_hash_hex(&script_hash(spk2.as_bytes()));

    let (dir, q) = temp_query("esplora-tcp");
    let q = Arc::new(q);
    let mp_dir = dir.join("mp");
    std::fs::create_dir_all(&mp_dir).unwrap();
    let hub = rbitcoin_net::MempoolHub::open(&mp_dir, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
    let handle = run_esplora(cfg, Arc::clone(&q), Some(Arc::clone(&hub)))
        .await
        .expect("listen");
    empty_chain_has_no_tip(handle.local_addr).await;

    let mut pad = HttpPad {
        q,
        hub,
        addr: handle.local_addr,
        cbs: Vec::new(),
        hashes: Vec::new(),
        tip_fk: Fk::NULL,
    };
    for h in 0..101u32 {
        let pay = match h {
            1 => vec![two_script_pay(0x11, spk1.clone())],
            2 => vec![two_script_pay(0x22, spk2.clone())],
            3 => vec![two_script_pay(0x33, spk1.clone())],
            _ => vec![],
        };
        pad.connect(pay);
    }
    tip_headers_and_powered_by(&pad).await;
    wallet_pages_after_txid(pad.addr, &sh1).await;
    wallet_posts_scripthashes(pad.addr, [&a1, &a2], [&sh1, &sh2]).await;
    tip_height_overlaps_scripthash_txs(&pad).await;
    let spend = mempool_spend_is_full_json(&pad).await;
    chain_cursor_matches_chain_page(&pad, &spend).await;
    mempool_spend_outspends_and_hex(&pad, &spend).await;
    confirmed_output_by_position(&pad).await;
    tx_by_position_matches_get_tx(&pad).await;
    batch_outputs_keep_order(&pad).await;
    junk_paths_asof_and_post(pad.addr, &pad.hashes[0]).await;
    same_height_replace_restamps(&mut pad).await;
    pruned_tail_is_partial_json(&mut pad).await;

    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// `max_connections` bounds the listener, not each route. Requests held on
/// one route fill it; a request on another route waits, and runs once a
/// slot frees.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn esplora_max_connections_spans_every_route() {
    const MAX: usize = 4;
    let (_dir, q) = temp_query("esplora-max-conn");
    let (h0, cb0) = coinbase(0, Fk::NULL, None);
    q.connect_block(Height(0), &h0, &[cb0]).unwrap();
    let mut cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
    cfg.limits.max_connections = MAX;
    let handle = run_esplora(cfg, Arc::new(q), None)
        .await
        .expect("listen");
    let addr = handle.local_addr;

    // A POST /tx whose body never arrives holds its slot in the extractor.
    let mut held = Vec::new();
    for _ in 0..MAX {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req = "POST /tx HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 64\r\n\r\n";
        stream.write_all(req.as_bytes()).await.unwrap();
        held.push(stream);
    }
    // One GET on another route must stay unanswered while the slots are
    // full. Retry while the held requests may not all be admitted yet.
    let mut tip = None;
    for _ in 0..20 {
        let before = handle.admit.waiting();
        let get = tokio::spawn(async move { http_get(addr, "/blocks/tip/height").await });
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let notified = handle.admit.notified();
            if !get.is_finished() && handle.admit.waiting() > before {
                tip = Some(get);
                break;
            }
            if get.is_finished() {
                break;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "a full listener did not queue the request"
            );
            if tokio::time::timeout(left, notified).await.is_err() {
                panic!("a full listener did not queue the request");
            }
        }
        if tip.is_some() {
            break;
        }
    }
    let tip = tip.expect("a full listener makes a request on another route wait");
    // Freeing one slot serves that same request.
    drop(held.pop());
    let (st, body) = tokio::time::timeout(Duration::from_secs(10), tip)
        .await
        .expect("a freed slot serves the waiting request")
        .unwrap();
    assert_eq!((st, body.as_str()), (200, "0"));
    handle.shutdown().await;
}

/// The request timeout covers the wait for a slot as well as the work, so a
/// queue of slow requests ahead cannot hold a later one past one timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn esplora_request_timeout_covers_the_wait_for_a_slot() {
    let (_dir, q) = temp_query("esplora-queue-timeout");
    let (h0, cb0) = coinbase(0, Fk::NULL, None);
    q.connect_block(Height(0), &h0, &[cb0]).unwrap();
    let mut cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
    cfg.limits.max_connections = 1;
    cfg.limits.idle_timeout = Duration::from_secs(1);
    let handle = run_esplora(cfg, Arc::new(q), None)
        .await
        .expect("listen");
    let addr = handle.local_addr;

    // Five POST /tx whose bodies never arrive queue for the one slot; each
    // holds it until the timeout once admitted.
    let mut held = Vec::new();
    for _ in 0..5 {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req = "POST /tx HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 64\r\n\r\n";
        stream.write_all(req.as_bytes()).await.unwrap();
        held.push(stream);
        let want = held.len();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let notified = handle.admit.notified();
            if handle.admit.arrived() >= want {
                break;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "held request never reached the listener ({}/{})",
                handle.admit.arrived(),
                want
            );
            if tokio::time::timeout(left, notified).await.is_err() {
                panic!(
                    "held request never reached the listener ({}/{})",
                    handle.admit.arrived(),
                    want
                );
            }
        }
    }
    let sent = Instant::now();
    let (st, _) = tokio::time::timeout(
        Duration::from_secs(10),
        http_get(addr, "/blocks/tip/height"),
    )
    .await
    .expect("no answer within 10s");
    let took = sent.elapsed();
    // The held requests' deadlines started before this one's, so their 408s
    // can free the slot just in time: either answer is within one timeout.
    assert!(
        st == 200 || st == 408,
        "the wait ends in an answer or the request timeout, got {st}"
    );
    assert!(
        took < Duration::from_millis(2500),
        "a request waited {took:?} behind the queue, past one 1s timeout"
    );
    drop(held);
    handle.shutdown().await;
}
