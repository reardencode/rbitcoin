use rbitcoin_log::progress::Snapshot;
use rbitcoin_node::health::metrics::*;
use std::time::{Duration, SystemTime};

fn assert_rpc_headers(hub: &std::sync::Arc<rbitcoin_net::ChainHub>, blocks: u32, headers: u32) {
    use rbitcoin_rpc::methods::{dispatch, RpcContext};
    let ctx = RpcContext {
        query: std::sync::Arc::clone(&hub.query),
        chain: Some(std::sync::Arc::clone(hub)),
        mempool: None,
        network: rbitcoin_primitives::Network::Regtest,
        start: std::time::Instant::now(),
        stop: Default::default(),
        connections: Default::default(),
        initial_block_download: Default::default(),
        subversion: String::new(),
        regtest: None,
        peers: None,
        addrman: None,
        logpath: String::new(),
        alert_notify: None,
        alert_fired: Default::default(),
        blocksonly: false,
        package_dialect: false,
        active: Default::default(),
    };
    let info = dispatch(&ctx, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(info["blocks"], blocks);
    assert_eq!(info["headers"], headers);
    let progress = if headers == 0 {
        1.0
    } else {
        f64::from(blocks) / f64::from(headers)
    };
    assert_eq!(info["verificationprogress"], progress);
}

#[tokio::test(flavor = "multi_thread")]
async fn ibd_header_height_survives_resume() {
    use bitcoin::hashes::Hash;
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_ibd::ibd::{apply_headers_event, header_walk, IbdWorkState};
    use rbitcoin_net::ChainHub;
    use rbitcoin_node::health::{router, NodeStatus, Phase};
    use rbitcoin_primitives::Network;
    use rbitcoin_query::Query;
    use rbitcoin_rpc::{HubRegtest, RpcRegtest};
    use std::sync::Arc;

    let (dir, hub, mut st) = tokio::task::spawn_blocking(|| {
        let _blocking = rbitcoin_net::reactor::BlockingRegion::enter();
        let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-metrics");
        let hub = Arc::new(hub);
        HubRegtest(Arc::clone(&hub))
            .generate_to_script(1, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![], true)
            .unwrap();
        hub.clock
            .set_mock(i64::from(hub.tip_header().unwrap().time) + 172_800);
        let st = IbdWorkState::new(vec![], hub.tip_hash(), hub.tip_height());
        (dir, hub, st)
    })
    .await
    .unwrap();
    let status = NodeStatus::new(Network::Regtest, false);
    status.chain.set(Arc::clone(&hub)).ok().unwrap();
    status.enter(Phase::CatchUp);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(Arc::clone(&status), true);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let m = super::get_soon(addr, "/metrics").await;
    assert!(m.contains("rbitcoin_blocks 1\n"), "{m}");
    assert!(m.contains("rbitcoin_headers 1\n"), "{m}");
    assert!(m.contains("rbitcoin_verification_progress 1\n"), "{m}");

    let h = Arc::clone(&hub);
    st = tokio::task::spawn_blocking(move || {
        let _blocking = rbitcoin_net::reactor::BlockingRegion::enter();
        let mut parent = h.tip_header().unwrap();
        let mut headers = Vec::new();
        for n in 2..=4 {
            let mut next = parent;
            next.prev_blockhash = parent.block_hash();
            next.merkle_root = bitcoin::TxMerkleNode::from_byte_array([n; 32]);
            next.time += 1;
            rbitcoin_consensus::grind_regtest_pow(&mut next);
            headers.push(next);
            parent = next;
        }
        header_walk::ensure_origin(&mut st, &h);
        apply_headers_event(&mut st, &h, 0, headers);
        assert_eq!(st.header_walk.tip_height(), 4);
        assert_rpc_headers(&h, 1, 4);
        st
    })
    .await
    .unwrap();
    let m = super::get_soon(addr, "/metrics").await;
    assert!(m.contains("rbitcoin_blocks 1\n"), "{m}");
    assert!(m.contains("rbitcoin_headers 4\n"), "{m}");
    assert!(m.contains("rbitcoin_verification_progress 0.25\n"), "{m}");
    assert!(m.contains("rbitcoin_ready 0\n"), "{m}");
    assert!(m.contains("rbitcoin_initial_block_download 1\n"), "{m}");

    server.abort();
    let _ = server.await;
    drop(status);
    drop(st);
    let path = dir.path().to_path_buf();
    let resumed = tokio::task::spawn_blocking(move || {
        let _blocking = rbitcoin_net::reactor::BlockingRegion::enter();
        hub.query.flush().unwrap();
        drop(hub);
        let hub = Arc::new(ChainHub::new(
            Query::open_or_create_tiny(path).unwrap(),
            ChainParams::regtest(),
            Milestone::NONE,
        ));
        hub.clock
            .set_mock(i64::from(hub.tip_header().unwrap().time) + 172_800);
        let mut st = IbdWorkState::new(vec![], hub.tip_hash(), hub.tip_height());
        assert!(header_walk::restore_adopt(&mut st, &hub));
        assert_eq!(st.header_walk.tip_height(), 4);
        assert_rpc_headers(&hub, 1, 4);
        (hub, st)
    })
    .await
    .unwrap();
    let (hub, mut st) = resumed;
    let status = NodeStatus::new(Network::Regtest, false);
    status.chain.set(Arc::clone(&hub)).ok().unwrap();
    status.enter(Phase::CatchUp);
    let addr = super::serve(router(status, true)).await;
    let m = super::get_soon(addr, "/metrics").await;
    assert!(m.contains("rbitcoin_blocks 1\n"), "{m}");
    assert!(m.contains("rbitcoin_headers 4\n"), "{m}");
    assert!(m.contains("rbitcoin_verification_progress 0.25\n"), "{m}");
    let (hub, mut st, connected) = tokio::task::spawn_blocking(move || {
        let _blocking = rbitcoin_net::reactor::BlockingRegion::enter();
        let connected = hub.tip_hash().unwrap();
        let mut parent = st.header_walk.tip_header().unwrap();
        let mut headers = Vec::new();
        for n in 5..=6 {
            let mut next = parent;
            next.prev_blockhash = parent.block_hash();
            next.merkle_root = bitcoin::TxMerkleNode::from_byte_array([n; 32]);
            next.time += 1;
            rbitcoin_consensus::grind_regtest_pow(&mut next);
            headers.push(next);
            parent = next;
        }
        assert!(header_walk::absorb_lookahead(
            &mut st,
            &hub,
            0,
            header_walk::HeaderAsk::InWindow,
            &headers
        ));
        assert!(!hub.knows_header(&parent.block_hash()));
        assert_rpc_headers(&hub, 1, 6);
        let mut rejected = HubRegtest(Arc::clone(&hub))
            .assemble_block_to_script(bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        rejected.header.time = hub.tip_header().unwrap().time + 1;
        rejected.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0]);
        rejected.header.merkle_root = rejected.compute_merkle_root().unwrap();
        rbitcoin_consensus::grind_regtest_pow(&mut rejected.header);
        let rejected_hash = rejected.block_hash();
        assert!(!hub.knows_header(&rejected_hash));
        assert_eq!(
            HubRegtest(Arc::clone(&hub)).submit_block(rejected),
            rbitcoin_rpc::methods::SubmitBlockOutcome::Rejected("bad-cb-length".into())
        );
        assert!(hub.knows_header(&rejected_hash));
        assert_rpc_headers(&hub, 1, 6);
        hub.reconsider_block(rejected_hash).unwrap();
        let mut sibling = hub.tip_header().unwrap();
        sibling.prev_blockhash = sibling.block_hash();
        sibling.time += 1;
        sibling.merkle_root = bitcoin::TxMerkleNode::from_byte_array([99; 32]);
        rbitcoin_consensus::grind_regtest_pow(&mut sibling);
        hub.ensure_header(&sibling).unwrap();
        hub.invalidate_block(sibling.block_hash()).unwrap();
        header_walk::publish_work(&mut st, &hub);
        assert_rpc_headers(&hub, 1, 6);
        let mut next = parent;
        next.prev_blockhash = parent.block_hash();
        next.time += 1;
        next.merkle_root = bitcoin::TxMerkleNode::from_byte_array([7; 32]);
        rbitcoin_consensus::grind_regtest_pow(&mut next);
        assert!(header_walk::absorb_lookahead(
            &mut st,
            &hub,
            0,
            header_walk::HeaderAsk::InWindow,
            &[next]
        ));
        assert_rpc_headers(&hub, 1, 7);
        let unstored_interior = headers[0];
        assert!(!hub.knows_header(&unstored_interior.block_hash()));
        hub.note_invalid_block(unstored_interior.block_hash());
        assert_rpc_headers(&hub, 1, 4);
        hub.ensure_header(&unstored_interior).unwrap();
        assert_rpc_headers(&hub, 1, 4);
        hub.reconsider_block(unstored_interior.block_hash())
            .unwrap();
        assert_rpc_headers(&hub, 1, 7);
        let checkpoint = hub.header_of(&st.header_walk.checkpoints[0].hash).unwrap();
        let interior = checkpoint.prev_blockhash;
        assert!(!st
            .header_walk
            .checkpoints
            .iter()
            .any(|c| c.hash == interior));
        hub.invalidate_block(interior).unwrap();
        header_walk::publish_work(&mut st, &hub);
        assert_rpc_headers(&hub, 1, 2);
        hub.reconsider_block(interior).unwrap();
        header_walk::publish_work(&mut st, &hub);
        assert_rpc_headers(&hub, 1, 7);
        let mut late_origin = IbdWorkState::new(vec![], hub.tip_hash(), hub.tip_height());
        let input = header_walk::origin_input(&late_origin, &hub);
        let loaded = header_walk::load_origin(&hub, &input);
        hub.invalidate_block(connected).unwrap();
        assert_rpc_headers(&hub, 0, 0);
        header_walk::publish_work(&mut st, &hub);
        assert_rpc_headers(&hub, 0, 0);
        header_walk::install_origin(&mut late_origin, &hub, loaded);
        assert_rpc_headers(&hub, 0, 0);
        let loaded_after = header_walk::load_origin(&hub, &input);
        let mut late_input = IbdWorkState::new(vec![], hub.tip_hash(), hub.tip_height());
        header_walk::install_origin(&mut late_input, &hub, loaded_after);
        assert_rpc_headers(&hub, 0, 0);
        (hub, st, connected)
    })
    .await
    .unwrap();
    let m = super::get_soon(addr, "/metrics").await;
    assert!(m.contains("rbitcoin_blocks 0\n"), "{m}");
    assert!(m.contains("rbitcoin_headers 0\n"), "{m}");
    tokio::task::spawn_blocking(move || {
        let _blocking = rbitcoin_net::reactor::BlockingRegion::enter();
        hub.reconsider_block(connected).unwrap();
        assert!(header_walk::restore_adopt(&mut st, &hub));
        assert_rpc_headers(&hub, 1, 7);
        header_walk::rewind_above(&mut st, &hub, 1);
        assert_eq!(
            hub.best_header_height(),
            5,
            "the stored frontier remains known after rewinding look-ahead"
        );
        assert_rpc_headers(&hub, 1, 5);
    })
    .await
    .unwrap();
}

fn stage(stage: &'static str, done: u64) -> Snapshot {
    Snapshot {
        stage,
        done,
        total: 10,
        base: 0,
        elapsed: Duration::ZERO,
        started_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
    }
}

/// Two running stages of one name (two nodes in one process) export one
/// series, the newest; each family's HELP/TYPE appears once; idle exports
/// nothing.
#[test]
fn progress_gauges_one_series_per_stage_name() {
    let mut out = Exposition::default();
    progress_gauges(&mut out, &[]);
    assert_eq!(out.0, "");

    let mut out = Exposition::default();
    progress_gauges(&mut out, &[stage("x", 1), stage("y", 5), stage("x", 2)]);
    let lines: Vec<&str> = out.0.lines().collect();
    let count = |prefix: &str| lines.iter().filter(|l| l.starts_with(prefix)).count();
    assert_eq!(count("rbitcoin_progress_done{stage=\"x\"}"), 1, "{}", out.0);
    assert!(
        lines.contains(&"rbitcoin_progress_done{stage=\"x\"} 2"),
        "{}",
        out.0
    );
    assert!(
        lines.contains(&"rbitcoin_progress_done{stage=\"y\"} 5"),
        "{}",
        out.0
    );
    assert!(lines.contains(&"rbitcoin_progress_target{stage=\"x\"} 10"));
    assert!(lines.contains(&"rbitcoin_progress_start_time_seconds{stage=\"x\"} 1000"));
    for family in [
        "rbitcoin_progress_done",
        "rbitcoin_progress_target",
        "rbitcoin_progress_start_time_seconds",
    ] {
        assert_eq!(count(&format!("# TYPE {family} gauge")), 1, "{}", out.0);
        assert_eq!(count(&format!("# HELP {family} ")), 1, "{}", out.0);
    }
}
