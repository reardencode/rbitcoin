use bitcoin::ScriptBuf;
use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_net::ChainHub;
use rbitcoin_query::Query;
use rbitcoin_rpc::HubRegtest;
use rbitcoin_rpc::RpcRegtest;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn hub_regtest_generate_one() {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-node-gen-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    let hub = Arc::new(ChainHub::new(
        Query::open_or_create_tiny(dir.join("store")).unwrap(),
        ChainParams::regtest(),
        Milestone::NONE,
    ));
    let miner = HubRegtest(hub);
    let hashes = miner
        .generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![], true)
        .unwrap();
    assert_eq!(hashes.len(), 1);
    assert_eq!(miner.0.tip_height(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hub_op_true_signet_generate_one() {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-node-signet-gen-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    let mut params = ChainParams::regtest();
    params.signet_challenge = Some(ScriptBuf::from_bytes(vec![0x51]));
    let hub = Arc::new(ChainHub::new(
        Query::open_or_create_tiny(dir.join("store")).unwrap(),
        params,
        Milestone::NONE,
    ));
    let miner = HubRegtest(hub);
    let hashes = miner
        .generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![], true)
        .unwrap();
    assert_eq!(hashes.len(), 1);
    assert_eq!(miner.0.tip_height(), Some(1));
    let bits = miner.0.tip_header().expect("tip").bits;
    assert_eq!(
        bits.to_consensus(),
        rbitcoin_consensus::REGTEST_POW_BITS,
        "the signet miner must grind the parent target, which is regtest here"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
