use bitcoin::consensus::{deserialize, encode::serialize_hex};
use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, ScriptBuf, Transaction};
use rbitcoin_net::MempoolHub;
use rbitcoin_primitives::Network;
use rbitcoin_query::Query;
use rbitcoin_rpc::methods::chain::*;
use rbitcoin_rpc::methods::mempool::*;
use rbitcoin_rpc::methods::mine::*;
use rbitcoin_rpc::methods::rest::dispatch_rest;
use rbitcoin_rpc::methods::*;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use bitcoin::{Address, Amount, Network as BtcNetwork, Txid};
use rbitcoin_primitives::Height;

use rbitcoin_store::testutil::TempDir;
use std::str::FromStr;
use std::time::Duration;

fn ctx_empty() -> (RpcContext, TempDir) {
    let dir = TempDir::labeled("rpc-meth").expect("temp dir");
    let ctx = open_ctx(&dir);
    (ctx, dir)
}

fn open_ctx(dir: &TempDir) -> RpcContext {
    let q = Arc::new(Query::open_or_create_tiny(dir.join("store")).unwrap());
    let mp =
        MempoolHub::open_with_weight(dir.join("mempool"), Arc::clone(&q), 300_000_000).unwrap();
    mp.set_relay_enabled(true);
    RpcContext {
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
        blocksonly: false,
    }
}

/// Genesis plus empty blocks `1..=102` (genesis time + 600s). `collect_coinbases`
/// does not change those block bytes, so the height-102 mempool tests share one pad.
struct Empty102Pad {
    store: std::path::PathBuf,
    _dir: TempDir,
    coinbases: Vec<Txid>,
}

fn empty_102_pad() -> &'static Empty102Pad {
    use std::sync::OnceLock;
    static PAD: OnceLock<Empty102Pad> = OnceLock::new();
    PAD.get_or_init(|| {
        let (ctx, dir) = ctx_empty();
        let params = rbitcoin_consensus::ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        rbitcoin_query::accept_and_connect_block(
            &ctx.query,
            &params,
            Height::GENESIS,
            &genesis,
            rbitcoin_consensus::Milestone::NONE,
        )
        .unwrap();
        let (_tip, _time, coinbases) = rbitcoin_query::pad_empty_from(
            &ctx.query,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            102,
            2,
        );
        ctx.query.flush().expect("flush empty-102 pad");
        Empty102Pad {
            store: dir.path().join("store"),
            _dir: dir,
            coinbases,
        }
    })
}

fn ctx_from_empty_102() -> (RpcContext, TempDir, Vec<Txid>) {
    let dir = TempDir::labeled("rpc-meth").expect("temp dir");
    let dest = dir.path().join("store");
    copy_store_tree(&empty_102_pad().store, &dest);
    let ctx = open_ctx(&dir);
    ctx.query.flush().expect("flush empty-102 copy");
    assert_eq!(ctx.query.tip_height(), Some(Height(102)));
    (ctx, dir, empty_102_pad().coinbases.clone())
}

#[test]
fn empty_102_pad_copy_keeps_the_other_tip() {
    use rbitcoin_consensus::{mine_empty_regtest, ChainParams, Milestone};
    use rbitcoin_query::accept_and_connect_block;

    let (a, dir_a, cbs_a) = ctx_from_empty_102();
    let (b, dir_b, cbs_b) = ctx_from_empty_102();
    assert_eq!(a.query.tip_height(), Some(Height(102)));
    assert_eq!(a.query.tip_height(), b.query.tip_height());
    let tip_a = a.query.reconstruct_block_at_height(Height(102)).unwrap();
    let tip_b = b.query.reconstruct_block_at_height(Height(102)).unwrap();
    assert_eq!(tip_a.block_hash(), tip_b.block_hash());
    assert_eq!(cbs_a, cbs_b);
    let h1_a = a.query.reconstruct_block_at_height(Height(1)).unwrap();
    let h1_b = b.query.reconstruct_block_at_height(Height(1)).unwrap();
    assert_eq!(h1_a.txdata[0].compute_txid(), h1_b.txdata[0].compute_txid());
    let next = mine_empty_regtest(tip_a.block_hash(), tip_a.header.time + 600, 103);
    accept_and_connect_block(
        &a.query,
        &ChainParams::regtest(),
        Height(103),
        &next,
        Milestone::NONE,
    )
    .unwrap();
    assert_ne!(a.query.tip_height(), Some(Height(102)));
    assert_eq!(
        b.query
            .reconstruct_block_at_height(Height(102))
            .unwrap()
            .block_hash(),
        tip_b.block_hash()
    );
    assert_eq!(b.query.tip_height(), Some(Height(102)));
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

fn named(obj: Value) -> RpcParams {
    RpcParams::named(obj.as_object().cloned().expect("object"))
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

const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const G_Y: &str = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

#[test]
fn decodescript_desc_matches_core() {
    let ff = "ff".repeat(32);
    let key = format!("02{G_X}");
    let push_key = format!("21{key}");
    let hybrid = format!("06{G_X}{G_Y}");
    let rows: Vec<(String, String)> = vec![
        (
            "0014751e76e8199196d454941c45d1b3a323f1433bd6".into(),
            "addr(bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080)#8pk5s7ya".into(),
        ),
        (
            "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac".into(),
            "addr(mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r)#wdmryvnu".into(),
        ),
        (
            "a914751e76e8199196d454941c45d1b3a323f1433bd687".into(),
            "addr(2N3vVYSK5XRgVSGWy21PnsRmBUywSQNdCsf)#zknva3nk".into(),
        ),
        (
            format!("0020{G_X}"),
            "addr(bcrt1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqjsgj9x)#7tlcs788"
                .into(),
        ),
        (format!("5120{G_X}"), format!("rawtr({G_X})#xsjqcczm")),
        (
            format!("5120{ff}"),
            "addr(bcrt1plllllllllllllllllllllllllllllllllllllllllllllllllllse0lp4e)#f6jd6wfe"
                .into(),
        ),
        (format!("{push_key}ac"), format!("pk({key})#gn28ywm7")),
        (
            format!("4104{G_X}{G_Y}ac"),
            format!("pk(04{G_X}{G_Y})#fsjyjr2x"),
        ),
        (format!("2103{ff}ac"), format!("pk(03{ff})#3se6jdc6")),
        (
            format!("41{hybrid}ac"),
            format!("raw(41{hybrid}ac)#qhj9gd8d"),
        ),
        (
            format!("4107{G_X}{G_Y}ac"),
            format!("raw(4107{G_X}{G_Y}ac)#z2cdvzds"),
        ),
        (
            format!("52{push_key}2103{G_X}52ae"),
            format!("multi(2,{key},03{G_X})#lex50jse"),
        ),
        (
            format!("51{}0111ae", push_key.repeat(17)),
            format!("multi(1,{})#58a7llg3", vec![key.as_str(); 17].join(",")),
        ),
        (
            format!("5141{hybrid}51ae"),
            format!("raw(5141{hybrid}51ae)#q4j8lzl0"),
        ),
        (
            format!("514107{G_X}{G_Y}51ae"),
            format!("raw(514107{G_X}{G_Y}51ae)#tlfhm7k4"),
        ),
        (
            format!("53{push_key}{push_key}52ae"),
            format!("raw(53{push_key}{push_key}52ae)#lgpsxqz8"),
        ),
        ("51024e73".into(), "addr(bcrt1pfeesnyr2tx)#swxgse0y".into()),
        ("5202abcd".into(), "addr(bcrt1z40xsz44l6p)#pj7n4prx".into()),
        ("51".into(), "raw(51)#8lvh9jxk".into()),
        ("6a04deadbeef".into(), "raw(6a04deadbeef)#uxzjket7".into()),
    ];
    let (mut ctx, dir) = ctx_empty();
    for (hex, desc) in &rows {
        let script = dispatch(&ctx, "decodescript", vec![json!(hex)]).unwrap();
        assert_eq!(script["desc"], json!(desc), "{hex}");
    }

    ctx.network = Network::Mainnet;
    let mainnet = dispatch(
        &ctx,
        "decodescript",
        vec![json!("0014751e76e8199196d454941c45d1b3a323f1433bd6")],
    )
    .unwrap();
    assert_eq!(
        mainnet["desc"],
        json!("addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)#uyjndxcw")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn decodescript_multisig_type_matches_core() {
    let push_key = format!("2102{G_X}");
    let keys = |n: usize| push_key.repeat(n);
    let rows: Vec<(String, &str)> = vec![
        ("5101ab51ae".into(), "nonstandard"),
        (format!("51{push_key}aeae"), "nonstandard"),
        (format!("51{push_key}0101ae"), "nonstandard"),
        (format!("514c{push_key}51ae"), "multisig"),
        (format!("51{}0111ae", keys(17)), "multisig"),
        (format!("51{}0114ae", keys(20)), "multisig"),
        (format!("51{}0115ae", keys(21)), "nonstandard"),
        (format!("0111{}0111ae", keys(17)), "multisig"),
        (format!("514106{G_X}{G_Y}51ae"), "multisig"),
    ];
    let (ctx, dir) = ctx_empty();
    for (hex, ty) in &rows {
        let script = dispatch(&ctx, "decodescript", vec![json!(hex)]).unwrap();
        assert_eq!(script["type"], json!(ty), "{hex}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn decodescript_witness_program_type_matches_core() {
    let program = |version: &str, len: usize| format!("{version}{len:02x}{}", "ab".repeat(len));
    let rows = [
        (program("00", 2), "nonstandard"),
        (program("00", 21), "nonstandard"),
        (program("00", 40), "nonstandard"),
        (program("00", 20), "witness_v0_keyhash"),
        (program("00", 32), "witness_v0_scripthash"),
        (program("51", 2), "witness_unknown"),
        ("51024e73".into(), "anchor"),
        (program("60", 40), "witness_unknown"),
        (program("51", 41), "nonstandard"),
    ];
    let (ctx, dir) = ctx_empty();
    for (hex, ty) in &rows {
        let script = dispatch(&ctx, "decodescript", vec![json!(hex)]).unwrap();
        assert_eq!(script["type"], json!(ty), "{hex}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn decodescript_pubkey_type_matches_core() {
    let ff = "ff".repeat(32);
    let rows: Vec<(String, &str)> = vec![
        (format!("2102{G_X}ac"), "pubkey"),
        (format!("2103{ff}ac"), "pubkey"),
        (format!("4104{G_X}{G_Y}ac"), "pubkey"),
        (format!("4106{G_X}{G_Y}ac"), "pubkey"),
        (format!("4107{G_X}{G_Y}ac"), "pubkey"),
        (format!("2100{G_X}ac"), "nonstandard"),
        (format!("2105{G_X}ac"), "nonstandard"),
        (format!("2104{G_X}ac"), "nonstandard"),
        (format!("4102{G_X}{G_Y}ac"), "nonstandard"),
        (format!("4c2102{G_X}ac"), "nonstandard"),
    ];
    let (ctx, dir) = ctx_empty();
    for (hex, ty) in &rows {
        let script = dispatch(&ctx, "decodescript", vec![json!(hex)]).unwrap();
        assert_eq!(script["type"], json!(ty), "{hex}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn decodescript_nulldata_type_matches_core() {
    let rows: Vec<(String, &str)> = vec![
        ("6a".into(), "nulldata"),
        ("6a0051504f60".into(), "nulldata"),
        ("6a4c01cd".into(), "nulldata"),
        (format!("6a4c64{}", "ab".repeat(100)), "nulldata"),
        ("6a4d0100ab".into(), "nulldata"),
        ("6a4e01000000ab".into(), "nulldata"),
        (format!("6a4d0902{}", "ab".repeat(521)), "nulldata"),
        ("6a61".into(), "nonstandard"),
        ("6aac".into(), "nonstandard"),
        ("6a6a".into(), "nonstandard"),
        ("6a01abac".into(), "nonstandard"),
        ("6a01".into(), "nonstandard"),
        ("6a4c".into(), "nonstandard"),
        ("6a4d0500ab".into(), "nonstandard"),
        ("6a4e05000000ab".into(), "nonstandard"),
    ];
    let (ctx, dir) = ctx_empty();
    for (hex, ty) in &rows {
        let script = dispatch(&ctx, "decodescript", vec![json!(hex)]).unwrap();
        assert_eq!(script["type"], json!(ty), "{hex}");
    }
    let _ = std::fs::remove_dir_all(&dir);
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

fn filter_header_hex(filter_hex: &str, parent_header_hex: &str) -> String {
    use bitcoin::bip158::{BlockFilter, FilterHeader};
    use bitcoin::hashes::Hash;
    let parent = FilterHeader::from_byte_array(
        rbitcoin_primitives::hex_decode(parent_header_hex)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let filter = BlockFilter::new(&rbitcoin_primitives::hex_decode(filter_hex).unwrap());
    rbitcoin_primitives::hex_encode(filter.filter_header(&parent).as_byte_array())
}

#[test]
fn getblockfilter_rebuilds_unsealed_and_chains_from_a_sealed_parent() {
    use bitcoin::bip158::BlockFilter;

    let (ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
    ctx.query.set_block_filter_index(true).unwrap();
    assert_eq!(ctx.query.filter_index_next(), Some(0));

    let missing = dispatch(&ctx, "getblockfilter", vec![json!("11".repeat(32))]).unwrap_err();
    assert_eq!(missing["code"], ERR_INVALID_ADDRESS_OR_KEY);
    assert_eq!(missing["message"], "Block not found");

    let tip = dispatch(&ctx, "getbestblockhash", vec![]).unwrap();
    let behind = dispatch(&ctx, "getblockfilter", vec![tip]).unwrap_err();
    assert_eq!(behind["code"], ERR_MISC);
    assert_eq!(
        behind["message"],
        "Filter not found. Block filters are still in the process of being indexed."
    );

    let genesis = dispatch(&ctx, "getblockhash", vec![json!(0)]).unwrap();
    let height1 = dispatch(&ctx, "getblockhash", vec![json!(1)]).unwrap();
    let height2 = dispatch(&ctx, "getblockhash", vec![json!(2)]).unwrap();
    let g = dispatch(&ctx, "getblockfilter", vec![genesis.clone()]).unwrap();
    let zero = "00".repeat(32);
    assert_eq!(
        g["header"],
        json!(filter_header_hex(g["filter"].as_str().unwrap(), &zero)),
        "genesis filter header chains from the zero prev-header"
    );
    let gap = dispatch(&ctx, "getblockfilter", vec![height1.clone()]).unwrap_err();
    assert_eq!(
        gap["message"],
        "Filter not found. Block filters are still in the process of being indexed.",
        "{gap}"
    );

    let body = rbitcoin_primitives::hex_decode(g["filter"].as_str().unwrap()).unwrap();
    let fk = ctx
        .query
        .store()
        .confirmed
        .get(Height(0))
        .unwrap()
        .expect("genesis header");
    assert_eq!(
        ctx.query
            .commit_window_filters(0, &[(BlockFilter::new(&body), fk)])
            .unwrap(),
        1
    );
    let one = dispatch(&ctx, "getblockfilter", vec![height1]).unwrap();
    assert_eq!(
        one["header"],
        json!(filter_header_hex(
            one["filter"].as_str().unwrap(),
            g["header"].as_str().unwrap(),
        )),
        "height 1 is built once its parent filter header is sealed, got {one}"
    );
    let still = dispatch(&ctx, "getblockfilter", vec![height2.clone()]).unwrap_err();
    assert_eq!(
        still["message"],
        "Filter not found. Block filters are still in the process of being indexed.",
        "{still}"
    );

    // Height 3's parent is height 2. Invalidating height 2 leaves both stale,
    // forked from height 1, whose filter is not sealed yet.
    let height3 = dispatch(&ctx, "getblockhash", vec![json!(3)]).unwrap();
    dispatch(&ctx, "invalidateblock", vec![height2.clone()]).unwrap();
    let stale_gap = dispatch(&ctx, "getblockfilter", vec![height3.clone()]).unwrap_err();
    assert_eq!(
        stale_gap["message"],
        "Filter not found. Block filters are still in the process of being indexed.",
        "{stale_gap}"
    );

    let one_body = rbitcoin_primitives::hex_decode(one["filter"].as_str().unwrap()).unwrap();
    let one_fk = ctx
        .query
        .store()
        .confirmed
        .get(Height(1))
        .unwrap()
        .expect("height 1 header");
    assert_eq!(
        ctx.query
            .commit_window_filters(1, &[(BlockFilter::new(&one_body), one_fk)])
            .unwrap(),
        1
    );
    let stale_two = dispatch(&ctx, "getblockfilter", vec![height2]).unwrap();
    assert_eq!(
        stale_two["header"],
        json!(filter_header_hex(
            stale_two["filter"].as_str().unwrap(),
            one["header"].as_str().unwrap(),
        )),
        "a stale block builds from its sealed best-chain parent, got {stale_two}"
    );
    let stale_three = dispatch(&ctx, "getblockfilter", vec![height3]).unwrap();
    assert_eq!(
        stale_three["header"],
        json!(filter_header_hex(
            stale_three["filter"].as_str().unwrap(),
            stale_two["header"].as_str().unwrap(),
        )),
        "a stale grandchild walks back to the sealed fork point, got {stale_three}"
    );
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

fn chainwork_f64(hex: &str) -> f64 {
    let b = rbitcoin_primitives::hex_decode(hex).unwrap();
    b.iter().fold(0.0, |a, x| a * 256.0 + f64::from(*x))
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
fn trust_peer_warning_line() {
    let (mut ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
    let no_disagreement = |method: &str, params: Vec<Value>| {
        let info = dispatch(&ctx, method, params).unwrap();
        let text = info["warnings"].to_string();
        assert!(
            !text.contains("disagreement"),
            "{method} flag off has no trust warning: {text}"
        );
    };
    no_disagreement("getnetworkinfo", vec![]);
    no_disagreement("getblockchaininfo", vec![]);
    let gbt = dispatch(&ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    match gbt.get("warnings") {
        None => {}
        Some(w) => {
            let arr = w
                .as_array()
                .unwrap_or_else(|| panic!("warnings is an array or absent: {gbt}"));
            assert!(!arr.is_empty(), "an empty warnings array is omitted: {gbt}");
            assert!(
                !arr.iter()
                    .any(|x| x.as_str().unwrap_or("").contains("disagreement")),
                "flag off has no trust warning: {gbt}"
            );
        }
    }

    let addr: std::net::SocketAddr = "1.2.3.4:8333".parse().unwrap();
    let peers = rbitcoin_net::PeerHub::new();
    peers.set_trust_peer(Some(rbitcoin_net::NetAddr::Ip(addr)), None);
    ctx.peers = Some(peers);
    ctx.query.set_trust_peer(true);
    let needle = "disagreements from trust-peer 1.2.3.4:8333 are warnings";
    for (method, params) in [
        ("getnetworkinfo", vec![]),
        ("getblockchaininfo", vec![]),
        ("getblocktemplate", vec![json!({"rules": ["segwit"]})]),
    ] {
        let info = dispatch(&ctx, method, params).unwrap();
        assert!(info.get("trustpeer").is_none(), "{method} adds no JSON key");
        let warnings = info["warnings"]
            .as_array()
            .unwrap_or_else(|| panic!("{method} warnings is an array: {info}"));
        let hits = warnings
            .iter()
            .filter(|w| w.as_str().unwrap_or("").contains("disagreement"))
            .count();
        assert_eq!(hits, 1, "{method} {warnings:?}");
        assert!(
            warnings.iter().any(|w| w.as_str() == Some(needle)),
            "{method} {warnings:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The standing trust line is not the one-shot `-alertnotify`. A later
/// version-bit warning can still fire it.
#[test]
fn trust_peer_warning_does_not_spend_alertnotify() {
    let (mut ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
    let alert = dir.path().join("alert.txt");
    ctx.alert_notify = Some(format!("echo %s >> {}", alert.display()));
    let addr: std::net::SocketAddr = "1.2.3.4:8333".parse().unwrap();
    let peers = rbitcoin_net::PeerHub::new();
    peers.set_trust_peer(Some(rbitcoin_net::NetAddr::Ip(addr)), None);
    ctx.peers = Some(peers);
    ctx.query.set_trust_peer(true);
    let info = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    let warnings = info["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().unwrap_or("").contains("disagreement")),
        "{warnings:?}"
    );
    assert!(
        !ctx.alert_fired.load(Ordering::SeqCst),
        "the trust line latched alertnotify"
    );
    assert!(
        !alert.exists(),
        "alertnotify ran for the trust line: {}",
        std::fs::read_to_string(&alert).unwrap_or_default()
    );
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
    let (ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
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
fn relay_off_empty_mempool_is_listed() {
    let (ctx, dir) = ctx_empty();
    ctx.mempool.as_ref().unwrap().set_relay_enabled(false);
    let raw = dispatch(&ctx, "getrawmempool", vec![]).unwrap();
    assert_eq!(raw, json!([]), "{raw}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn relay_off_empty_pool_serves_template() {
    let (ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
    ctx.mempool.as_ref().unwrap().set_relay_enabled(false);
    let gbt = dispatch(&ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    assert!(gbt.get("height").is_some(), "{gbt}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn relay_off_refuses_pool_listing_and_mines_coinbase_only() {
    let (ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
    let (hex, spend) = mature_coinbase_spend_hex(&ctx, 50_0000_0000 - 1_000);
    dispatch(&ctx, "sendrawtransaction", vec![json!(hex)]).unwrap();
    ctx.mempool.as_ref().unwrap().set_relay_enabled(false);
    let hashes = dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let hash = hashes[0].as_str().unwrap();
    let block = dispatch(&ctx, "getblock", vec![json!(hash)]).unwrap();
    assert_eq!(block["nTx"].as_u64(), Some(1), "{block}");
    assert!(ctx
        .mempool
        .as_ref()
        .unwrap()
        .contains(&spend.compute_txid()));
    let gbt = dispatch(&ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap_err();
    assert_eq!(gbt["code"], -10, "{gbt}");
    let raw = dispatch(&ctx, "getrawmempool", vec![]).unwrap_err();
    assert_eq!(raw["code"], -10, "{raw}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn template_follows_the_stripped_tip() {
    let (ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
    let tip = dispatch(&ctx, "getbestblockhash", vec![]).unwrap();
    let (_, genesis) = ctx
        .query
        .header_at_height(Height(0))
        .unwrap()
        .expect("genesis");
    ctx.mempool
        .as_ref()
        .unwrap()
        .note_template_prev(genesis.hash);
    let gbt = dispatch(&ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    let prev = gbt["previousblockhash"].as_str().unwrap();
    assert_ne!(prev, tip.as_str().unwrap(), "{gbt}");
    assert_eq!(gbt["height"].as_u64(), Some(1), "{gbt}");
    assert!(
        gbt["longpollid"].as_str().unwrap().starts_with(prev),
        "{gbt}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn template_follows_the_fork_after_invalidate() {
    let (ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
    let tip = dispatch(&ctx, "getbestblockhash", vec![]).unwrap();
    let blk = dispatch(&ctx, "getblock", vec![tip.clone(), json!(1)]).unwrap();
    let parent = blk["previousblockhash"].clone();
    let height = blk["height"].as_u64().unwrap();
    dispatch(&ctx, "invalidateblock", vec![tip]).unwrap();
    let gbt = dispatch(&ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    assert_eq!(gbt["previousblockhash"], parent, "{gbt}");
    assert_eq!(gbt["height"].as_u64(), Some(height), "{gbt}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn template_follows_the_fork_after_header_rewind() {
    let (ctx, dir, hub) = ctx_from_mature_pad(300_000_000);
    let tip = dispatch(&ctx, "getbestblockhash", vec![]).unwrap();
    let blk = dispatch(&ctx, "getblock", vec![tip, json!(1)]).unwrap();
    let parent = blk["previousblockhash"].clone();
    let height = blk["height"].as_u64().unwrap();
    hub.rewind_to_height(u32::try_from(height - 1).unwrap())
        .unwrap();
    let gbt = dispatch(&ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    assert_eq!(gbt["previousblockhash"], parent, "{gbt}");
    assert_eq!(gbt["height"].as_u64(), Some(height), "{gbt}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn template_follows_blocks_the_hub_connects() {
    let (ctx, dir, _hub) = ctx_regtest_hub();
    dispatch(&ctx, "generate", vec![json!(2)]).unwrap();
    let gbt = dispatch(&ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    assert_eq!(gbt["height"].as_u64(), Some(3), "{gbt}");
    let mut bare = ctx_without_chain(&ctx);
    bare.mempool = None;
    let bare_gbt = dispatch(
        &bare,
        "getblocktemplate",
        vec![json!({"rules": ["segwit"]})],
    )
    .unwrap();
    assert_eq!(bare_gbt["height"].as_u64(), Some(3), "{bare_gbt}");
    assert_eq!(dispatch(&bare, "getrawmempool", vec![]).unwrap(), json!([]));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn blocksonly_lists_mempool_mines_and_refuses_template() {
    let (mut ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
    ctx.blocksonly = true;
    ctx.mempool.as_ref().unwrap().set_relay_enabled(true);
    let (hex, spend) = mature_coinbase_spend_hex(&ctx, 50_0000_0000 - 1_000);
    let ok = dispatch(&ctx, "sendrawtransaction", vec![json!(hex)]).unwrap();
    let txid = spend.compute_txid().to_string();
    assert_eq!(ok.as_str().unwrap(), &txid);
    let raw = dispatch(&ctx, "getrawmempool", vec![]).unwrap();
    assert_eq!(raw, json!([txid]), "{raw}");
    let gbt = dispatch(&ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap_err();
    assert_ne!(gbt["code"], -10, "{gbt}");
    assert!(
        gbt["message"].as_str().unwrap_or("").contains("blocksonly"),
        "{gbt}"
    );
    let hashes = dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    assert_eq!(hashes.as_array().map(Vec::len), Some(1), "{hashes}");
    let hash = hashes[0].as_str().unwrap();
    let block = dispatch(&ctx, "getblock", vec![json!(hash)]).unwrap();
    assert_eq!(block["nTx"].as_u64(), Some(2), "{block}");
    assert!(!ctx
        .mempool
        .as_ref()
        .unwrap()
        .contains(&spend.compute_txid()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Production `-blocksonly` never turns relay on. `generate` still mines the
/// pool transaction and that txid is gone before the RPC returns. A strip
/// that no-ops while relay is off would leave it listed.
#[test]
fn blocksonly_generate_removes_the_tx_it_mines() {
    let (mut ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
    ctx.blocksonly = true;
    ctx.mempool.as_ref().unwrap().set_relay_enabled(false);
    let (hex, spend) = mature_coinbase_spend_hex(&ctx, 50_0000_0000 - 1_000);
    let txid = spend.compute_txid();
    dispatch(&ctx, "sendrawtransaction", vec![json!(hex)]).unwrap();
    let hashes = dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let hash = hashes[0].as_str().unwrap();
    let block = dispatch(&ctx, "getblock", vec![json!(hash)]).unwrap();
    assert_eq!(block["nTx"].as_u64(), Some(2), "{block}");
    assert!(
        !ctx.mempool.as_ref().unwrap().contains(&txid),
        "mined tx still live"
    );
    let raw = dispatch(&ctx, "getrawmempool", vec![]).unwrap();
    assert_eq!(raw, json!([]), "{raw}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// More blocks than the cap is refused before any block is mined. The pool
/// transactions chosen for that call stay live.
#[test]
fn generate_over_cap_leaves_the_pool() {
    let (ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
    let (hex, spend) = mature_coinbase_spend_hex(&ctx, 50_0000_0000 - 1_000);
    let txid = spend.compute_txid();
    dispatch(&ctx, "sendrawtransaction", vec![json!(hex)]).unwrap();
    let err = dispatch(&ctx, "generate", vec![json!(10_001)]).unwrap_err();
    assert!(
        ctx.mempool.as_ref().unwrap().contains(&txid),
        "failed generate wiped the pool: {err}"
    );
    let raw = dispatch(&ctx, "getrawmempool", vec![]).unwrap();
    assert_eq!(raw, json!([txid.to_string()]), "{raw}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The block that holds the pool transactions can be accepted while a later
/// block in the same `generate` fails. Those txids have to be gone already:
/// the next `generate` would select them again and could not connect them.
#[test]
fn generate_later_block_failure_still_drops_the_mined_tx() {
    let (mut ctx, dir, hub) = ctx_from_mature_pad(300_000_000);
    ctx.blocksonly = true;
    ctx.mempool.as_ref().unwrap().set_relay_enabled(false);
    let (hex, spend) = mature_coinbase_spend_hex(&ctx, 50_0000_0000 - 1_000);
    let txid = spend.compute_txid();
    dispatch(&ctx, "sendrawtransaction", vec![json!(hex)]).unwrap();
    let before = dispatch(&ctx, "getblockcount", vec![])
        .unwrap()
        .as_u64()
        .unwrap();
    hub.generate_fail_before.store(1, Ordering::Relaxed);
    let err = dispatch(&ctx, "generate", vec![json!(2)]).unwrap_err();
    hub.generate_fail_before.store(0, Ordering::Relaxed);
    assert!(
        !ctx.mempool.as_ref().unwrap().contains(&txid),
        "accepted block left its tx in the pool: {err}"
    );
    let raw = dispatch(&ctx, "getrawmempool", vec![]).unwrap();
    assert_eq!(raw, json!([]), "{raw}");
    let height = dispatch(&ctx, "getblockcount", vec![])
        .unwrap()
        .as_u64()
        .unwrap();
    assert_eq!(
        height,
        before + 1,
        "only the block with the tx was accepted"
    );
    let tip = dispatch(&ctx, "getbestblockhash", vec![]).unwrap();
    let block = dispatch(&ctx, "getblock", vec![tip]).unwrap();
    assert_eq!(block["nTx"].as_u64(), Some(2), "{block}");
    let hashes = dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let hash = hashes[0].as_str().unwrap();
    let next = dispatch(&ctx, "getblock", vec![json!(hash)]).unwrap();
    assert_eq!(next["nTx"].as_u64(), Some(1), "{next}");
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
fn hash_hex_display_matches_blockhash_display_and_reverses_parse() {
    // Fixed non-palindrome internal bytes.
    let mut internal = [0u8; 32];
    for (i, b) in internal.iter_mut().enumerate() {
        *b = i as u8;
    }
    let disp = hash_hex_display(&internal);
    let via_type = rbitcoin_primitives::display_hash_hex(internal);
    assert_eq!(disp, via_type);
    let back = parse_hash32_display(&disp).unwrap();
    assert_eq!(back, internal);
    assert_ne!(disp, rbitcoin_primitives::hex_encode(internal));
}

#[test]
fn all_methods_callable_empty_or_error() {
    let (ctx, dir) = ctx_empty();
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
        blocksonly: false,
    };
    let mem2 = dispatch(&ctx2, "getmempoolinfo", vec![]).unwrap();
    assert_eq!(mem2["loaded"], true);
    let raw = dispatch(&ctx2, "getrawmempool", vec![json!(true)]).unwrap();
    assert_eq!(raw, json!({}));
    let gbt = dispatch(
        &ctx2,
        "getblocktemplate",
        vec![json!({"rules": ["segwit"]})],
    )
    .unwrap_err();
    assert!(
        gbt["message"].as_str().unwrap_or("").contains("no tip"),
        "{gbt}"
    );
    assert_ne!(gbt["code"], -10, "{gbt}");
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
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_primitives::Height;
    use rbitcoin_query::accept_and_connect_block;

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
    let (_tip, _tip_time, coinbase_txids) = rbitcoin_query::pad_empty_from(
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
    assert_eq!(miss_raw["code"], ERR_INVALID_ADDRESS_OR_KEY);
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
    let (ctx, dir, coinbase_txids) = ctx_from_empty_102();
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

    let (ctx, dir, coinbase_txids) = ctx_from_empty_102();
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
    let want = bitcoin::Weight::from_wu(weight).to_vbytes_ceil();
    let fund_v = bitcoin::Weight::from_wu(fund.weight().to_wu()).to_vbytes_ceil();
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
fn ctx_regtest_hub() -> (RpcContext, TempDir, Arc<rbitcoin_net::ChainHub>) {
    ctx_regtest_hub_with_weight(300_000_000)
}

fn ctx_regtest_hub_with_weight(max_wu: u64) -> (RpcContext, TempDir, Arc<rbitcoin_net::ChainHub>) {
    ctx_regtest_hub_on(rbitcoin_consensus::ChainParams::regtest(), max_wu)
}

fn ctx_regtest_hub_on(
    params: rbitcoin_consensus::ChainParams,
    max_wu: u64,
) -> (RpcContext, TempDir, Arc<rbitcoin_net::ChainHub>) {
    let dir = TempDir::labeled("rpc-gen").expect("temp dir");
    let hub = open_regtest_hub(dir.join("store"), params);
    hub.ensure_genesis().unwrap();
    regtest_ctx(dir, hub, max_wu)
}

/// One 101-block regtest chain for tests that only need a mature coinbase.
/// Each caller copies the store and opens a fresh mempool.
fn mature_regtest_pad() -> &'static MatureRegtestPad {
    use std::sync::OnceLock;
    static PAD: OnceLock<MatureRegtestPad> = OnceLock::new();
    PAD.get_or_init(|| {
        let (ctx, dir, hub) = ctx_regtest_hub();
        dispatch(&ctx, "generate", vec![json!(101)]).unwrap();
        ctx.query.flush().expect("flush mature pad");
        let store = dir.path().join("store");
        MatureRegtestPad {
            store,
            _dir: dir,
            _hub: hub,
        }
    })
}

struct MatureRegtestPad {
    store: std::path::PathBuf,
    _dir: TempDir,
    _hub: Arc<rbitcoin_net::ChainHub>,
}

fn ctx_from_mature_pad(max_wu: u64) -> (RpcContext, TempDir, Arc<rbitcoin_net::ChainHub>) {
    let dir = TempDir::labeled("rpc-gen").expect("temp dir");
    let dest = dir.path().join("store");
    copy_store_tree(&mature_regtest_pad().store, &dest);
    let hub = open_regtest_hub(&dest, rbitcoin_consensus::ChainParams::regtest());
    hub.ensure_genesis().unwrap();
    regtest_ctx(dir, hub, max_wu)
}

#[test]
fn mature_pad_copy_keeps_the_other_tip() {
    let (a, dir_a, hub_a) = ctx_from_mature_pad(300_000_000);
    let (_b, dir_b, hub_b) = ctx_from_mature_pad(300_000_000);
    assert_eq!(hub_a.tip_height(), hub_b.tip_height());
    assert!(hub_a.tip_height().unwrap() >= 101);
    let tip_b = hub_b.tip_hash().unwrap();
    assert_eq!(hub_a.tip_hash().unwrap(), tip_b);
    let h1_a = hub_a.query.reconstruct_block_at_height(Height(1)).unwrap();
    let h1_b = hub_b.query.reconstruct_block_at_height(Height(1)).unwrap();
    assert_eq!(h1_a.txdata[0].compute_txid(), h1_b.txdata[0].compute_txid());
    dispatch(&a, "generate", vec![json!(1)]).unwrap();
    assert_ne!(hub_a.tip_hash().unwrap(), tip_b);
    assert_eq!(hub_b.tip_hash().unwrap(), tip_b);
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

fn open_regtest_hub(
    store: impl AsRef<std::path::Path>,
    params: rbitcoin_consensus::ChainParams,
) -> Arc<rbitcoin_net::ChainHub> {
    Arc::new(rbitcoin_net::ChainHub::new(
        Query::open_or_create_tiny(store).unwrap(),
        params,
        rbitcoin_consensus::Milestone::NONE,
    ))
}

fn regtest_ctx(
    dir: TempDir,
    hub: Arc<rbitcoin_net::ChainHub>,
    max_wu: u64,
) -> (RpcContext, TempDir, Arc<rbitcoin_net::ChainHub>) {
    let mp = MempoolHub::open_with_weight(dir.join("mempool"), hub.query.clone(), max_wu).unwrap();
    // The node attaches this pool before it serves RPC. Connects and
    // disconnects move the template mark on that same pool.
    assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());
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
        regtest: Some(Arc::new(HubRegtest(Arc::clone(&hub)))),
        peers: None,
        chain: Some(Arc::clone(&hub)),
        addrman: None,

        logpath: String::new(),
        active: std::sync::Arc::new(std::sync::Mutex::new(RpcActive::default())),

        alert_notify: None,
        alert_fired: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        blocksonly: false,
    };
    (ctx, dir, hub)
}

fn copy_store_tree(src: &std::path::Path, dst: &std::path::Path) {
    rbitcoin_store::testutil::copy_store_tree(src, dst);
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

    let (ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
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

fn object_keys(v: &serde_json::Value) -> Vec<&str> {
    v.as_object()
        .expect("header object")
        .keys()
        .map(String::as_str)
        .collect()
}

/// `serde_json::Map` walks in sorted order (`preserve_order` is off). This is
/// the order `keys()` and `to_string` show for an active header with no
/// previous or next hash.
const HEADER_KEYS_ACTIVE: &[&str] = &[
    "bits",
    "chainwork",
    "confirmations",
    "difficulty",
    "hash",
    "height",
    "mediantime",
    "merkleroot",
    "nTx",
    "nonce",
    "target",
    "time",
    "version",
    "versionHex",
];

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
    assert_eq!(
        object_keys(&genesis_hdr),
        HEADER_KEYS_ACTIVE,
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
    let mut parent_keys = HEADER_KEYS_ACTIVE.to_vec();
    parent_keys.push("nextblockhash");
    parent_keys.sort_unstable();
    assert_eq!(object_keys(&parent), parent_keys, "{parent}");
    let tip = dispatch(&ctx, "getbestblockhash", vec![]).unwrap();
    let tip_hdr = dispatch(&ctx, "getblockheader", vec![tip.clone()]).unwrap();
    assert!(tip_hdr.get("nextblockhash").is_none(), "{tip_hdr}");
    let mut tip_keys = HEADER_KEYS_ACTIVE.to_vec();
    tip_keys.push("previousblockhash");
    tip_keys.sort_unstable();
    assert_eq!(object_keys(&tip_hdr), tip_keys, "{tip_hdr}");
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

    let tip = dispatch(&ctx, "getbestblockhash", vec![]).unwrap();
    let blk = dispatch(&ctx, "getblock", vec![tip, json!(1)]).unwrap();
    let txid = blk["tx"].as_array().unwrap()[0].as_str().unwrap();
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

/// Core never adds an unspendable output to the UTXO set, so `gettxout` is
/// null for a confirmed `OP_RETURN` or a script over 10,000 bytes. A script
/// of exactly 10,000 bytes is still a coin. REST `getutxos` follows.
#[test]
fn gettxout_unspendable_confirmed_output_is_null() {
    use bitcoin::TxOut;
    let (ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
    let (_, mut spend) = mature_coinbase_spend_hex(&ctx, 50_0000_0000 - 101_000);
    spend.output.push(TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x07]),
    });
    let mut big = vec![0x51];
    big.resize(10_001, 0x61);
    spend.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(big),
    });
    spend.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(vec![0x51; 10_000]),
    });
    let hex = rbitcoin_primitives::hex_encode(bitcoin::consensus::encode::serialize(&spend));
    let (addr, _) = p2wpkh_regtest();
    dispatch(&ctx, "generateblock", vec![json!(addr), json!([hex])]).unwrap();
    let txid = hash_hex_display(&spend.compute_txid().to_byte_array());
    let coin = dispatch(&ctx, "gettxout", vec![json!(txid), json!(0)]).unwrap();
    assert!(!coin.is_null(), "a spendable output is a coin");
    let boundary = dispatch(&ctx, "gettxout", vec![json!(txid), json!(3)]).unwrap();
    assert_eq!(
        boundary["scriptPubKey"]["hex"].as_str().map(str::len),
        Some(20_000),
        "a 10,000-byte script is still a coin: {boundary}"
    );
    for n in [1, 2] {
        let out = dispatch(&ctx, "gettxout", vec![json!(txid), json!(n)]).unwrap();
        assert!(out.is_null(), "unspendable vout {n} is not a coin: {out}");
    }
    let (status, body) = rest_text(
        &ctx,
        &format!("/rest/getutxos/{txid}-0/{txid}-1/{txid}-2/{txid}-3.json"),
        "",
    );
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body.contains("\"bitmap\":\"1001\""), "{body}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gettxout_leftover_is_connected_not_unconfirmed() {
    let (ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
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
    dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let tid = spend.compute_txid();
    let txid = hash_hex_display(&tid.to_byte_array());
    assert!(
        !ctx.mempool.as_ref().unwrap().contains(&tid),
        "generate must drop a tx it just confirmed"
    );
    let gbt = dispatch(&ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    let republished = gbt["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["txid"].as_str() == Some(txid.as_str()));
    assert!(
        !republished,
        "template must not contain a tx the new tip already confirmed: {gbt}"
    );
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

/// `gettxout` describes its coin with the same `scriptPubKey` object as
/// `getrawtransaction`, in the mempool and once confirmed: Core's `type`
/// and, for a standard script, `address`.
#[test]
fn gettxout_script_pubkey_matches_getrawtransaction() {
    let (ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
    let p2wpkh = ScriptBuf::from_bytes([&[0x00, 0x14][..], &[0x07; 20]].concat());
    let (hex, spend) = mature_coinbase_spend(&ctx, 50_0000_0000 - 1_000, p2wpkh);
    dispatch(&ctx, "sendrawtransaction", vec![json!(hex)]).unwrap();
    let txid = hash_hex_display(&spend.compute_txid().to_byte_array());
    let described = || {
        let raw = dispatch(&ctx, "getrawtransaction", vec![json!(txid), json!(true)]).unwrap();
        raw["vout"][0]["scriptPubKey"].clone()
    };

    let unconfirmed = dispatch(&ctx, "gettxout", vec![json!(txid), json!(0)]).unwrap();
    assert_eq!(unconfirmed["confirmations"], 0, "{unconfirmed}");
    assert_eq!(unconfirmed["scriptPubKey"], described());
    assert_eq!(unconfirmed["scriptPubKey"]["type"], "witness_v0_keyhash");
    assert!(
        unconfirmed["scriptPubKey"]["address"]
            .as_str()
            .unwrap()
            .starts_with("bcrt1q"),
        "{unconfirmed}"
    );

    dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let confirmed = dispatch(&ctx, "gettxout", vec![json!(txid), json!(0)]).unwrap();
    assert_eq!(confirmed["confirmations"], 1, "{confirmed}");
    assert_eq!(confirmed["scriptPubKey"], described());
    let _ = std::fs::remove_dir_all(&dir);
}

fn mature_coinbase_spend(
    ctx: &RpcContext,
    keep_sat: u64,
    script: ScriptBuf,
) -> (String, Transaction) {
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
    (rbitcoin_primitives::hex_encode(serialize(&spend)), spend)
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
    let vsize = bitcoin::Weight::from_wu(weight).to_vbytes_ceil();
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
    let (ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
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
    let (ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
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
    let bad_hex = rbitcoin_primitives::hex_encode(serialize(&bad));
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
fn submitpackage_maxfeerate_skips_package_eval_and_reports_replacements() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let (ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
    let (low_hex, low) = spend_generated_coinbase(
        &ctx,
        1,
        50_0000_0000 - 1_000,
        ScriptBuf::from_bytes(vec![0x51]),
    );
    dispatch(&ctx, "sendrawtransaction", vec![json!(low_hex), json!(0)]).unwrap();
    let parent = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: low.input[0].previous_output.txid,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 2_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
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
            value: Amount::from_sat(50_0000_0000 - 12_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x52]),
        }],
    };
    let parent_vb = bitcoin::Weight::from_wu(parent.weight().to_wu()).to_vbytes_ceil();
    let child_vb = bitcoin::Weight::from_wu(child.weight().to_wu()).to_vbytes_ceil();
    let parent_fee = 2_000u64;
    let child_fee = 10_000u64;
    let max_feerate = parent_fee.div_ceil(parent_vb.max(1));
    assert!(
        parent_fee <= max_feerate.saturating_mul(parent_vb),
        "parent fee must stay within maxfeerate {max_feerate}"
    );
    assert!(
        child_fee > max_feerate.saturating_mul(child_vb),
        "child fee must exceed maxfeerate {max_feerate} vsize {child_vb}"
    );
    let pkg = dispatch(
        &ctx,
        "submitpackage",
        vec![
            json!([
                rbitcoin_primitives::hex_encode(serialize(&parent)),
                rbitcoin_primitives::hex_encode(serialize(&child))
            ]),
            json!(max_feerate),
        ],
    )
    .unwrap();
    assert_eq!(pkg["package_msg"], "transaction failed", "{pkg}");
    let child_w = hash_hex_display(&child.compute_wtxid().to_byte_array());
    assert_eq!(
        pkg["tx-results"][&child_w]["error"],
        json!("max feerate exceeded"),
        "{pkg}"
    );
    let low_txid = hash_hex_display(&low.compute_txid().to_byte_array());
    assert_eq!(
        pkg["replaced-transactions"],
        json!([low_txid]),
        "the replacement parent must name the tx it evicted, got {pkg}"
    );
    let mp = ctx.mempool.as_ref().unwrap();
    assert!(mp.contains(&parent.compute_txid()));
    assert!(!mp.contains(&child.compute_txid()));
    assert!(!mp.contains(&low.compute_txid()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rpc_submit_nonstandard_version_is_version() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let (ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
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
    let child_hex = rbitcoin_primitives::hex_encode(serialize(&child));
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
    // Spend a confirmed coin. A version-3 child of the version-2 parent
    // above is a TRUC ancestor mismatch, which is a separate rule.
    let (_, fresh) = mature_coinbase_spend(&ctx, 4_999_998_000, ScriptBuf::from_bytes(vec![0x51]));
    let mut v3 = fresh;
    v3.version = TxVersion::non_standard(3);
    let v3_hex = rbitcoin_primitives::hex_encode(serialize(&v3));
    let sent = dispatch(&ctx, "sendrawtransaction", vec![json!(v3_hex)]).unwrap();
    assert_eq!(
        sent.as_str().unwrap(),
        v3.compute_txid().to_string(),
        "{sent}"
    );
    assert!(
        ctx.mempool.as_ref().unwrap().contains(&v3.compute_txid()),
        "version 3 must enter the mempool"
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

    let (ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
    pressure_same_rate_evicts_the_lighter_chunk(&ctx);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let (parent_hex, parent) = spend_generated_coinbase(&ctx, 1, 50_0000_0000 - 1_000, spk.clone());
    let child = child_of(&parent, 1_000);
    let child_hex = rbitcoin_primitives::hex_encode(serialize(&child));

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
        vec![json!([
            parent_hex.clone(),
            rbitcoin_primitives::hex_encode(serialize(&garbage))
        ])],
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
    let conflict_hex = rbitcoin_primitives::hex_encode(serialize(&conflict_b));
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

    // Height 3's coinbase is one block short of maturity on the 101-block pad.
    dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    pressure_admit_then_cluster(&ctx, &spk);

    // Parent is under the relay floor alone. The pool is already heavier than
    // the package, and the cap fits the package only. Trimming between the
    // two members used to evict the parent and answer `mempool full`.
    let (low_hex, low_parent) = spend_generated_coinbase(&ctx, 3, 50_0000_0000 - 1, spk.clone());
    let low_child = child_of(&low_parent, 80_000);
    let low_child_hex = rbitcoin_primitives::hex_encode(serialize(&low_child));
    let mp = ctx.mempool.as_ref().unwrap();
    mp.set_max_weight(low_parent.weight().to_wu() + low_child.weight().to_wu());
    let kept = dispatch(&ctx, "submitpackage", vec![json!([low_hex, low_child_hex])]).unwrap();
    assert_eq!(kept["package_msg"], "success", "{kept}");
    assert!(mp.contains(&low_parent.compute_txid()));
    assert!(mp.contains(&low_child.compute_txid()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Fee 501 at vsize 5000 and 5001 both floor to 100 sat/kvB and both clear
/// min relay. The lighter txid is linearized first, so the two children stay
/// two chunks. A weight cap that fits the parent and the heavier child drops
/// the lighter one. `<=` in the worst-chunk walk would drop the heavier one.
fn pressure_same_rate_evicts_the_lighter_chunk(ctx: &RpcContext) {
    chain_ops_mine_pool_empty(ctx);
    let tip = dispatch(ctx, "getblockcount", vec![])
        .unwrap()
        .as_u64()
        .unwrap();
    if tip < 105 {
        dispatch(ctx, "generate", vec![json!(105 - tip)]).unwrap();
    }
    let mp = ctx.mempool.as_ref().unwrap();
    mp.set_max_weight(300_000_000);
    let cb = generated_coinbase_value(ctx, 4);
    let each = (cb - 10_000) / 2;
    let light_lens = p2wsh_item_lens(5_000);
    let heavy_lens = p2wsh_item_lens(5_001);
    let light_proto = p2wsh_with_lens(bitcoin::OutPoint::null(), each, 501, 1, &light_lens);
    let heavy_proto = p2wsh_with_lens(bitcoin::OutPoint::null(), each, 501, 1, &heavy_lens);
    let parent = parent_paying(
        ctx,
        4,
        each,
        p2wsh_spk(&light_proto),
        p2wsh_spk(&heavy_proto),
    );
    let pid = parent.compute_txid();
    dispatch(ctx, "sendrawtransaction", vec![json!(tx_hex(&parent))]).unwrap();
    let (light, heavy) = (1..400u32)
        .find_map(|n| {
            let light = p2wsh_with_lens(
                bitcoin::OutPoint { txid: pid, vout: 0 },
                each,
                501,
                n,
                &light_lens,
            );
            let heavy = p2wsh_with_lens(
                bitcoin::OutPoint { txid: pid, vout: 1 },
                each,
                501,
                n + 400,
                &heavy_lens,
            );
            (light.compute_txid() < heavy.compute_txid()).then_some((light, heavy))
        })
        .expect("a lighter txid before the heavier sibling");
    assert_eq!(
        rbitcoin_consensus::policy::fee_rate_sat_per_kvb(501, light.weight().to_wu()),
        rbitcoin_consensus::policy::fee_rate_sat_per_kvb(501, heavy.weight().to_wu()),
    );
    dispatch(ctx, "sendrawtransaction", vec![json!(tx_hex(&light))]).unwrap();
    dispatch(ctx, "sendrawtransaction", vec![json!(tx_hex(&heavy))]).unwrap();
    let probe_cb = generated_coinbase_value(ctx, 5);
    let (probe_hex, probe) = spend_generated_coinbase(ctx, 5, probe_cb - 20_000, true_spk());
    mp.set_max_weight(parent.weight().to_wu() + heavy.weight().to_wu() + probe.weight().to_wu());
    dispatch(ctx, "sendrawtransaction", vec![json!(probe_hex)]).unwrap();
    let raw = dispatch(ctx, "getrawmempool", vec![]).unwrap();
    let listed = |tx: &Transaction| {
        let want = tx.compute_txid().to_string();
        raw.as_array()
            .unwrap()
            .iter()
            .any(|id| id.as_str() == Some(want.as_str()))
    };
    assert!(listed(&parent), "parent stays");
    assert!(listed(&heavy), "heavier sibling stays");
    assert!(
        !listed(&light),
        "the earlier equal-rate chunk is the one evicted"
    );
    assert!(listed(&probe), "the arriving tx stays");
    chain_ops_mine_pool_empty(ctx);
    mp.set_max_weight(300_000_000);
}

fn p2wsh_script(n_drops: usize) -> ScriptBuf {
    let mut bytes = vec![0x75u8; n_drops];
    bytes.push(0x51);
    ScriptBuf::from_bytes(bytes)
}

fn witness_script(tx: &Transaction) -> ScriptBuf {
    let last = tx.input[0].witness.iter().last().expect("witness script");
    ScriptBuf::from_bytes(last.to_vec())
}

fn p2wsh_spk(tx: &Transaction) -> ScriptBuf {
    ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::hash(witness_script(tx).as_bytes()))
}

/// Witness-item lengths for a P2WSH `OP_DROP`…`OP_TRUE` spend of `target_vsize`.
/// Stack items stay at or under 520 bytes. The shape does not depend on the prevout.
fn p2wsh_item_lens(target_vsize: u64) -> Vec<usize> {
    let mut lens = Vec::new();
    loop {
        let tx = p2wsh_with_lens(bitcoin::OutPoint::null(), 1_000_000, 1, 1, &lens);
        let vsize = bitcoin::Weight::from_wu(tx.weight().to_wu()).to_vbytes_ceil();
        if vsize == target_vsize {
            return lens;
        }
        assert!(
            vsize < target_vsize,
            "vsize {vsize} overshot {target_vsize}"
        );
        if lens.last().copied().unwrap_or(520) >= 520 {
            lens.push(1);
        } else {
            *lens.last_mut().unwrap() += 1;
        }
        assert!(
            lens.len() < 180,
            "witness pad did not reach vsize {target_vsize}"
        );
    }
}

/// P2WSH `OP_DROP`…`OP_TRUE` spend. `lens` is from [`p2wsh_item_lens`].
fn p2wsh_with_lens(
    prev: bitcoin::OutPoint,
    value_in: u64,
    fee: u64,
    nonce: u32,
    lens: &[usize],
) -> Transaction {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Sequence, TxIn, TxOut, Witness};
    let script = p2wsh_script(lens.len());
    let mut stack: Vec<Vec<u8>> = lens.iter().copied().map(|n| vec![0u8; n]).collect();
    stack.push(script.to_bytes());
    let refs: Vec<&[u8]> = stack.iter().map(Vec::as_slice).collect();
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prev,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(0x8000_0000 | nonce),
            witness: Witness::from_slice(&refs),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value_in - fee),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn parent_paying(
    ctx: &RpcContext,
    height: u32,
    each: u64,
    script0: ScriptBuf,
    script1: ScriptBuf,
) -> Transaction {
    use bitcoin::TxOut;
    let (_, proto) = spend_generated_coinbase(ctx, height, 1, ScriptBuf::from_bytes(vec![0x51]));
    Transaction {
        version: proto.version,
        lock_time: proto.lock_time,
        input: proto.input,
        output: vec![
            TxOut {
                value: Amount::from_sat(each),
                script_pubkey: script0,
            },
            TxOut {
                value: Amount::from_sat(each),
                script_pubkey: script1,
            },
        ],
    }
}

#[test]
fn pressure_tiny_weight() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let (fee_ctx, fee_dir, _fee_hub) = ctx_from_mature_pad(1_000);
    let info = dispatch(&fee_ctx, "getmempoolinfo", vec![]).unwrap();
    let minrelay = info["minrelaytxfee"].as_f64().unwrap();
    let minfee = info["mempoolminfee"].as_f64().unwrap();
    assert!(
        minfee > minrelay,
        "tiny weight cap must raise mempoolminfee: {info}"
    );
    let cb = generated_coinbase_value(&fee_ctx, 1);
    let probe = spend_generated_coinbase(&fee_ctx, 1, cb - 1, spk.clone()).1;
    let vsize = bitcoin::Weight::from_wu(probe.weight().to_wu()).to_vbytes_ceil();
    let minrelay_fee = vsize.div_ceil(10);
    let (low_hex, low) = spend_generated_coinbase(&fee_ctx, 1, cb - minrelay_fee, spk.clone());
    // Child fee stays under the default 10_000 sat/vB `maxfeerate`. A 1 sat
    // output would burn almost the whole coinbase and skip package eval.
    let child_fee = 1_000u64;
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
            value: Amount::from_sat(cb - minrelay_fee - child_fee),
            script_pubkey: spk,
        }],
    };
    let child_vb = bitcoin::Weight::from_wu(low_child.weight().to_wu()).to_vbytes_ceil();
    assert!(
        child_fee <= 10_000u64.saturating_mul(child_vb),
        "child fee {child_fee} must stay within default maxfeerate, vsize {child_vb}"
    );
    let pkg = dispatch(
        &fee_ctx,
        "submitpackage",
        vec![json!([
            low_hex,
            rbitcoin_primitives::hex_encode(serialize(&low_child))
        ])],
    )
    .unwrap();
    assert_eq!(pkg["package_msg"], "success", "{pkg}");
    let parent_w = hash_hex_display(&low.compute_wtxid().to_byte_array());
    let child_w = hash_hex_display(&low_child.compute_wtxid().to_byte_array());
    assert_eq!(
        pkg["tx-results"][&parent_w]["fees"]["effective-includes"].clone(),
        json!([parent_w, child_w]),
        "paying child must clear the dynamic floor with the parent, got {pkg}"
    );
    assert!(fee_ctx
        .mempool
        .as_ref()
        .unwrap()
        .contains(&low.compute_txid()));
    assert!(fee_ctx
        .mempool
        .as_ref()
        .unwrap()
        .contains(&low_child.compute_txid()));
    let _ = std::fs::remove_dir_all(&fee_dir);
}

fn pressure_admit_then_cluster(ctx: &RpcContext, spk: &ScriptBuf) {
    use bitcoin::consensus::encode::serialize;
    // Parent and child are under the relay floor. The grandchild pays for
    // the chain. A package walk that stops at the direct parent does not
    // admit them.
    let (chain_hex, chain_parent) = spend_generated_coinbase(ctx, 2, 50_0000_0000 - 1, spk.clone());
    let chain_child = child_of(&chain_parent, 1);
    let chain_grand = child_of(&chain_child, 80_000);
    let chain_child_hex = rbitcoin_primitives::hex_encode(serialize(&chain_child));
    let chain = dispatch(
        ctx,
        "submitpackage",
        vec![json!([
            chain_hex.clone(),
            chain_child_hex.clone(),
            rbitcoin_primitives::hex_encode(serialize(&chain_grand))
        ])],
    )
    .unwrap();
    assert_eq!(chain["package_msg"], "success", "{chain}");
    let admitted = ctx.mempool.as_ref().unwrap();
    assert!(admitted.contains(&chain_parent.compute_txid()), "{chain}");
    assert!(admitted.contains(&chain_child.compute_txid()), "{chain}");
    assert!(admitted.contains(&chain_grand.compute_txid()), "{chain}");
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
            rbitcoin_primitives::hex_encode(serialize(&cluster_child)),
            rbitcoin_primitives::hex_encode(serialize(&cluster_grand))
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
    let (ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
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
    let child_hex = rbitcoin_primitives::hex_encode(serialize(&child));
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
fn generate_selects_chained_mempool_parent_first() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_consensus::ChainParams;
    use rbitcoin_query::pad_empty_from;

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
    let parent_hex = rbitcoin_primitives::hex_encode(serialize(&parent));
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
        vec![json!(rbitcoin_primitives::hex_encode(serialize(&child)))],
    )
    .unwrap();
    dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let tip = dispatch(&ctx, "getbestblockhash", vec![]).unwrap();
    let mined = dispatch(&ctx, "getblock", vec![tip, json!(1)]).unwrap();
    let txids = mined["tx"].as_array().unwrap();
    assert_eq!(txids.len(), 3, "coinbase + parent + child: {mined}");
    assert_eq!(txids[1], parent_id);
    assert_eq!(txids[2], child_id);

    let cb_hex = hash_hex_display(&cb_txid.to_byte_array());
    let spent = dispatch(&ctx, "gettxout", vec![json!(cb_hex), json!(0)]).unwrap();
    assert!(spent.is_null(), "spent coinbase is not unspent: {spent}");
    let child_out = dispatch(&ctx, "gettxout", vec![child_id.clone(), json!(0)]).unwrap();
    assert_eq!(child_out["coinbase"], false, "{child_out}");

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
        vec![json!(rbitcoin_primitives::hex_encode(serialize(&bad)))],
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
    let want = rbitcoin_rpc::blockstats::compute_block_stats(
        1,
        &block,
        rbitcoin_query::median_time_past(hub.query.as_ref(), Height(1))
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
        vec![json!(rbitcoin_primitives::hex_encode(serialize(&spend)))],
    )
    .unwrap();
    dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let tip_hash = dispatch(&ctx, "getbestblockhash", vec![]).unwrap();

    let v1 = dispatch(&ctx, "getblock", vec![tip_hash.clone(), json!(1)]).unwrap();

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
    let want = rbitcoin_rpc::blockstats::compute_block_stats(
        h,
        &block,
        rbitcoin_query::median_time_past(hub.query.as_ref(), Height(h))
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
                value: Amount::from_sat(out.value),
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
    let net = dispatch(&ctx, "getnetworkinfo", vec![]).unwrap();
    assert_eq!(net["connections_in"], 1);
    assert_eq!(net["connections_out"], 1);
    assert_eq!(net["connections"], 2);
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
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_primitives::Height;
    use rbitcoin_query::accept_and_connect_block;

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
    let (_tip, _tip_time, coinbase_txids) = rbitcoin_query::pad_empty_from(
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
    let high_hex = rbitcoin_primitives::hex_encode(serialize(&high));
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
    let hex = rbitcoin_primitives::hex_encode(serialize(&tx));
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

    let spend = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: b1.txdata[0].compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: Amount::from_sat(1),
            script_pubkey: op_true.clone(),
        }],
    };
    let b3 = rbitcoin_consensus::mine_regtest_paying(
        b2.block_hash(),
        t0 + 5,
        3,
        op_true.clone(),
        vec![spend],
    );
    let e = dispatch(&ctx, "submitblock", vec![json!(block_hex(&b3))])
        .expect_err("a spent-output read fault is not bad-txns-inputs-missingorspent");
    assert_eq!(e["code"], ERR_VERIFY_ERROR, "{e}");
    assert!(
        e["message"]
            .as_str()
            .unwrap_or_default()
            .starts_with("store: "),
        "{e}"
    );
    assert!(!hub.is_block_invalid(&b3.block_hash()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Core `GetMinimumTime`: `mintime` is the lowest time the next block can
/// carry, one past the tip median. At genesis that median is its time.
#[test]
fn getblocktemplate_mintime_is_one_past_the_tip_median() {
    let (ctx, dir, hub) = ctx_from_mature_pad(300_000_000);
    let gbt = dispatch(&ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    let tip = Height(hub.tip_height().unwrap());
    let mtp = rbitcoin_query::median_time_past(hub.query.as_ref(), tip).unwrap();
    assert_eq!(gbt["mintime"], u64::from(mtp) + 1, "{gbt}");
    let _ = std::fs::remove_dir_all(&dir);

    let (ctx, dir, hub) = ctx_regtest_hub();
    let gbt = dispatch(&ctx, "getblocktemplate", vec![json!({"rules": ["segwit"]})]).unwrap();
    let genesis = hub.tip_header().unwrap().time;
    assert_eq!(gbt["mintime"], u64::from(genesis) + 1, "{gbt}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A sibling that spends the coin the current tip also spent is a competing
/// block, not a permanent `duplicate-invalid`.
#[test]
fn submitblock_sibling_spend_is_not_cached_invalid() {
    use rbitcoin_primitives::Height;

    let (ctx, dir, hub) = ctx_from_mature_pad(300_000_000);
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    let mature = hub.query.reconstruct_block_at_height(Height(1)).unwrap();
    let spend = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: mature.txdata[0].compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: Amount::from_sat(1),
            script_pubkey: op_true.clone(),
        }],
    };
    let parent = hub.tip_hash().unwrap();
    let t0 = hub.tip_header().unwrap().time;
    let height = hub.tip_height().unwrap() + 1;
    let b2 = rbitcoin_consensus::mine_regtest_paying(
        parent,
        t0 + 1,
        height,
        op_true.clone(),
        vec![spend.clone()],
    );
    let r = dispatch(&ctx, "submitblock", vec![json!(block_hex(&b2))]).unwrap();
    assert!(r.is_null(), "{r}");
    let sibling =
        rbitcoin_consensus::mine_regtest_paying(parent, t0 + 2, height, op_true, vec![spend]);
    let r = dispatch(&ctx, "submitblock", vec![json!(block_hex(&sibling))]).unwrap();
    assert_eq!(r, "inconclusive", "{r}");
    assert!(
        !hub.is_block_invalid(&sibling.block_hash()),
        "a competing spend must stay submittable"
    );
    let again = dispatch(&ctx, "submitblock", vec![json!(block_hex(&sibling))]).unwrap();
    assert_ne!(again, "duplicate-invalid", "{again}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A side-branch child may spend an output its held parent created. Core
/// checks those inputs when the branch connects, so the child reorgs.
#[test]
fn submitblock_child_spends_its_side_parent_output() {
    let (ctx, dir, hub) = ctx_from_mature_pad(300_000_000);
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    let spend = |txid: Txid, sats: u64| Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: op_true.clone(),
        }],
    };
    let mature = hub.query.reconstruct_block_at_height(Height(1)).unwrap();
    let x = spend(mature.txdata[0].compute_txid(), 2);
    let y = spend(x.compute_txid(), 1);
    let height = hub.tip_height().unwrap();
    let (_, fork) = hub
        .query
        .header_at_height(Height(height - 1))
        .unwrap()
        .unwrap();
    let t0 = hub.tip_header().unwrap().time;
    let b1 = rbitcoin_consensus::mine_regtest_paying(
        bitcoin::BlockHash::from_byte_array(fork.hash),
        t0 + 1,
        height,
        op_true.clone(),
        vec![x],
    );
    let r = dispatch(&ctx, "submitblock", vec![json!(block_hex(&b1))]).unwrap();
    assert_eq!(r, "inconclusive", "{r}");
    let b2 = rbitcoin_consensus::mine_regtest_paying(
        b1.block_hash(),
        t0 + 2,
        height + 1,
        op_true.clone(),
        vec![y],
    );
    let r = dispatch(&ctx, "submitblock", vec![json!(block_hex(&b2))]).unwrap();
    assert!(r.is_null(), "{r}");
    assert_eq!(hub.tip_hash(), Some(b2.block_hash()));
    assert!(!hub.is_block_invalid(&b2.block_hash()));

    // A heavier side branch whose inputs fail at connect keeps Core's reason.
    let coinbase_at = |h: u32| {
        hub.query
            .reconstruct_block_at_height(Height(h))
            .unwrap()
            .txdata[0]
            .compute_txid()
    };
    let overspend = spend(coinbase_at(2), 50_0000_0001);
    let first = spend(coinbase_at(3), 1);
    let mut second = first.clone();
    second.output[0].value = Amount::from_sat(2);
    let immature = spend(coinbase_at(height - 1), 1);
    // `None` spends the side parent's own coinbase.
    for (i, (txs, reason)) in [
        (Some(vec![overspend]), "bad-txns-in-belowout"),
        (Some(vec![first, second]), "bad-txns-inputs-missingorspent"),
        (Some(vec![immature]), "bad-txns-premature-spend-of-coinbase"),
        (None, "bad-txns-premature-spend-of-coinbase"),
    ]
    .into_iter()
    .enumerate()
    {
        let c1 = rbitcoin_consensus::mine_regtest_paying(
            b1.block_hash(),
            t0 + 10 + i as u32,
            height + 1,
            op_true.clone(),
            vec![],
        );
        let r = dispatch(&ctx, "submitblock", vec![json!(block_hex(&c1))]).unwrap();
        assert_eq!(r, "inconclusive", "{r}");
        let txs = txs.unwrap_or_else(|| vec![spend(c1.txdata[0].compute_txid(), 1)]);
        let c2 = rbitcoin_consensus::mine_regtest_paying(
            c1.block_hash(),
            t0 + 20 + i as u32,
            height + 2,
            op_true.clone(),
            txs,
        );
        let r = dispatch(&ctx, "submitblock", vec![json!(block_hex(&c2))]).unwrap();
        assert_eq!(r, reason);
        assert_eq!(hub.tip_hash(), Some(b2.block_hash()));
        let again = dispatch(&ctx, "submitblock", vec![json!(block_hex(&c2))]).unwrap();
        assert_eq!(again, "duplicate-invalid");
    }

    // A block on the tip still takes the early input check.
    let on_tip = rbitcoin_consensus::mine_regtest_paying(
        b2.block_hash(),
        t0 + 30,
        height + 2,
        op_true.clone(),
        vec![spend(coinbase_at(2), 50_0000_0001)],
    );
    let r = dispatch(&ctx, "submitblock", vec![json!(block_hex(&on_tip))]).unwrap();
    assert_eq!(r, "bad-txns-in-belowout");
    assert_eq!(hub.tip_hash(), Some(b2.block_hash()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Core `CheckTxInputs`: a confirmed txid with no output at `vout` is a
/// missing input, not a store fault.
#[test]
fn submitblock_vout_past_n_out_is_missingorspent() {
    let (ctx, dir, hub) = ctx_regtest_hub();
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    let t0 = hub.tip_header().unwrap().time;
    let b1 = rbitcoin_consensus::mine_regtest_paying(
        hub.tip_hash().unwrap(),
        t0 + 1,
        1,
        op_true.clone(),
        vec![],
    );
    let r = dispatch(&ctx, "submitblock", vec![json!(block_hex(&b1))]).unwrap();
    assert!(r.is_null(), "{r}");
    let past_end = u32::try_from(b1.txdata[0].output.len()).unwrap();
    for vout in [past_end, past_end + 1, u32::MAX - 1] {
        let spend = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: b1.txdata[0].compute_txid(),
                    vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: Amount::from_sat(1),
                script_pubkey: op_true.clone(),
            }],
        };
        let b2 = rbitcoin_consensus::mine_regtest_paying(
            b1.block_hash(),
            t0 + 2,
            2,
            op_true.clone(),
            vec![spend],
        );
        let r = dispatch(&ctx, "submitblock", vec![json!(block_hex(&b2))])
            .unwrap_or_else(|e| panic!("vout {vout} is a consensus reject, not an RPC error: {e}"));
        assert_eq!(r, "bad-txns-inputs-missingorspent", "vout {vout}");
        assert_eq!(hub.tip_hash(), Some(b1.block_hash()));
        assert!(
            hub.is_block_invalid(&b2.block_hash()),
            "vout {vout}: submitblock caches the consensus reject"
        );
        let again = dispatch(&ctx, "submitblock", vec![json!(block_hex(&b2))]).unwrap();
        assert_eq!(again, "duplicate-invalid", "vout {vout}");

        let err = hub
            .accept_received_block(b2.clone())
            .expect_err("tip connect rejects the same spend");
        let err_s = err.to_string();
        assert!(
            err_s.contains("bad-txns-inputs-missingorspent")
                || err_s.contains("block is invalidated"),
            "vout {vout}: {err_s}"
        );
        assert!(
            hub.is_block_invalid(&b2.block_hash()),
            "vout {vout}: the tip path caches the consensus reject"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Core `UpdateUncommittedBlockStructures`: a coinbase with a witness
/// commitment and no witness gets the 32 zero bytes once segwit is active.
/// Below segwit the commitment is plain data and the coinbase stays bare.
/// A reserved value the miner already set is kept, a block with no
/// commitment is left alone, and a parent known only as a header counts.
#[test]
fn submitblock_adds_the_witness_reserved_value_once_segwit_is_active() {
    let mut params = rbitcoin_consensus::ChainParams::regtest();
    params.apply_test_activation_height("segwit", 2).unwrap();
    let (ctx, dir, hub) = ctx_regtest_hub_on(params, 300_000_000);
    let mk = |prev: BlockHash, time: u32, height: u32, commit: Option<[u8; 32]>, own: bool| {
        let mut b = rbitcoin_consensus::mine_regtest_paying(
            prev,
            time,
            height,
            ScriptBuf::from_bytes(vec![0x51]),
            vec![],
        );
        if let Some(reserved) = commit {
            if own {
                b.txdata[0].input[0].witness = bitcoin::Witness::from_slice(&[reserved]);
            }
            let commitment = rbitcoin_consensus::witness_commitment_script([], &reserved);
            b.txdata[0].output.push(bitcoin::TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(commitment),
            });
            b.header.merkle_root = b.compute_merkle_root().unwrap();
            regrind(&mut b);
        }
        b
    };
    let submit = |b: &Block| dispatch(&ctx, "submitblock", vec![json!(block_hex(b))]).unwrap();
    let mut prev = (hub.tip_hash().unwrap(), hub.tip_header().unwrap().time);
    let zero = Some([0u8; 32]);
    for (height, commit, own) in [
        (1u32, zero, false),
        (2, zero, false),
        (3, Some([7u8; 32]), true),
        (4, None, false),
    ] {
        let b = mk(prev.0, prev.1 + 1, height, commit, own);
        let r = submit(&b);
        assert!(r.is_null(), "height {height}: {r}");
        assert_eq!(hub.tip_hash(), Some(b.block_hash()), "height {height}");
        prev = (b.block_hash(), b.header.time);
    }
    // Headers first: once its child's header arrives, h5 is a stored header
    // with no body and no longer a header tip.
    let b5 = mk(prev.0, prev.1 + 1, 5, None, false);
    let b6 = mk(b5.block_hash(), prev.1 + 2, 6, zero, false);
    for b in [&b5, &b6] {
        dispatch(&ctx, "submitheader", vec![json!(serialize_hex(&b.header))]).unwrap();
    }
    assert_eq!(submit(&b6), "inconclusive", "held until h5's body");
    assert!(submit(&b5).is_null());
    assert_eq!(hub.tip_hash(), Some(b6.block_hash()));

    let coinbase_witness = |h: u32| {
        let b = hub.query.reconstruct_block_at_height(Height(h)).unwrap();
        b.txdata[0].input[0].witness.to_vec()
    };
    assert!(coinbase_witness(1).is_empty(), "no fill below segwit");
    assert_eq!(coinbase_witness(2), vec![vec![0u8; 32]]);
    assert_eq!(coinbase_witness(3), vec![vec![7u8; 32]]);
    assert!(
        coinbase_witness(4).is_empty(),
        "no fill without a commitment"
    );
    assert_eq!(coinbase_witness(6), vec![vec![0u8; 32]]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A store fault reading the parent header is not `prev-blk-not-found`,
/// and on the tip-extend path it is not a reject reason that gets cached.
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
    let b3 = mine_on(b2.block_hash(), 3, t0 + 4);
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

    for attempt in 0..2 {
        let e = dispatch(&ctx, "submitblock", vec![json!(block_hex(&b3))])
            .expect_err("a tip header read fault is an RPC error");
        assert_eq!(e["code"], ERR_VERIFY_ERROR, "attempt {attempt}: {e}");
        assert!(
            !hub.is_block_invalid(&b3.block_hash()),
            "attempt {attempt}: a tip header read fault is not a block verdict"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Same store and mempool as `src`, without a chain hub. `run_rpc` takes
/// `chain: Option`; the node always passes one, and this is the other shape.
fn ctx_without_chain(src: &RpcContext) -> RpcContext {
    RpcContext {
        query: Arc::clone(&src.query),
        mempool: src.mempool.clone(),
        network: src.network,
        start: src.start,
        stop: Arc::clone(&src.stop),
        connections: Arc::clone(&src.connections),
        initial_block_download: Arc::clone(&src.initial_block_download),
        subversion: src.subversion.clone(),
        regtest: src.regtest.clone(),
        peers: None,
        chain: None,
        addrman: src.addrman.clone(),
        logpath: src.logpath.clone(),
        active: Arc::clone(&src.active),
        alert_notify: src.alert_notify.clone(),
        alert_fired: Arc::clone(&src.alert_fired),
        blocksonly: src.blocksonly,
    }
}

fn rpc_message(err: &Value) -> &str {
    err["message"].as_str().unwrap_or("")
}

fn loose_tx(version: i32, marker: u8, prev: bitcoin::OutPoint, value: u64) -> Transaction {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Sequence, TxIn, TxOut, Witness};
    Transaction {
        version: TxVersion::non_standard(version),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prev,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![marker, 0x51]),
        }],
    }
}

fn marker_outpoint(marker: u8) -> bitcoin::OutPoint {
    bitcoin::OutPoint {
        txid: Txid::from_byte_array([marker; 32]),
        vout: 0,
    }
}

/// Client-visible RPC and REST results for branches the other lib tests never
/// take: no chain hub, a held equal-work body, a header-only submit, package
/// rows, and the parameter errors those methods return.
#[allow(clippy::cognitive_complexity)]
#[test]
fn shipped_rpc_reads_cover_fallback_and_reject_arms() {
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::{Block, CompactTarget, OutPoint};

    let (ctx, dir, hub) = ctx_regtest_hub();
    let bare = ctx_without_chain(&ctx);
    dispatch(&ctx, "generate", vec![json!(1)]).unwrap();
    let tip_time = dispatch(
        &ctx,
        "getblockheader",
        vec![dispatch(&ctx, "getbestblockhash", vec![]).unwrap()],
    )
    .unwrap()["time"]
        .as_u64()
        .unwrap();
    dispatch(&ctx, "setmocktime", vec![json!(tip_time + 1_000)]).unwrap();
    dispatch(&ctx, "generate", vec![json!(1)]).unwrap();

    let tips = dispatch(&bare, "getchaintips", vec![]).unwrap();
    assert_eq!(tips[0]["status"], "active", "{tips}");
    assert_eq!(tips[0]["branchlen"], 0, "{tips}");
    assert_eq!(tips[0]["height"], json!(tip_count(&ctx)), "{tips}");
    let hps = dispatch(&bare, "getnetworkhashps", vec![json!(120)]).unwrap();
    assert!(
        hps.as_f64().unwrap_or(0.0) > 0.0,
        "two headers with different times produce a hashrate: {hps}"
    );
    let at_zero = dispatch(&bare, "getnetworkhashps", vec![json!(120), json!(0)]).unwrap();
    assert_eq!(at_zero, json!(0.0), "{at_zero}");
    let truncated = dispatch(&bare, "getnetworkhashps", vec![json!(4_294_967_296i64)]).unwrap();
    assert_eq!(truncated, json!(0.0), "{truncated}");
    let info = dispatch(&bare, "getblockchaininfo", vec![]).unwrap();
    assert_eq!(info["chainwork"].as_str().unwrap().len(), 64, "{info}");

    for (net, name) in [
        (Network::Mainnet, "main"),
        (Network::Testnet, "test"),
        (Network::Signet, "signet"),
    ] {
        let mut labeled = ctx_without_chain(&ctx);
        labeled.network = net;
        let info = dispatch(&labeled, "getblockchaininfo", vec![]).unwrap();
        assert_eq!(info["chain"], name, "{info}");
    }

    let gbt = dispatch(
        &bare,
        "getblocktemplate",
        vec![json!({"rules": ["segwit"]})],
    )
    .unwrap();
    assert_eq!(
        gbt["previousblockhash"].as_str().unwrap().len(),
        64,
        "{gbt}"
    );
    assert_eq!(gbt["rules"][0], "segwit", "{gbt}");
    let no_segwit =
        dispatch(&ctx, "getblocktemplate", vec![json!({"rules": ["csv"]})]).unwrap_err();
    assert!(
        rpc_message(&no_segwit).contains("segwit rule set"),
        "{no_segwit}"
    );
    let bad_mode = dispatch(
        &ctx,
        "getblocktemplate",
        vec![json!({"rules": ["segwit"], "mode": "future"})],
    )
    .unwrap_err();
    assert!(
        rpc_message(&bad_mode).contains("Invalid mode"),
        "{bad_mode}"
    );
    let (empty, empty_dir) = ctx_empty();
    let no_tip = dispatch(
        &empty,
        "getblocktemplate",
        vec![json!({"rules": ["segwit"]})],
    )
    .unwrap_err();
    assert!(rpc_message(&no_tip).contains("no tip"), "{no_tip}");
    let _ = std::fs::remove_dir_all(&empty_dir);

    let early = dispatch(&ctx, "estimaterawfee", vec![json!(2)]).unwrap();
    assert_eq!(early["feerate"], json!(-1.0), "{early}");
    assert!(
        early["errors"].to_string().contains("Insufficient data"),
        "{early}"
    );
    let mut no_mp = ctx_without_chain(&ctx);
    no_mp.mempool = None;
    let unavailable = dispatch(&no_mp, "estimaterawfee", vec![json!(3)]).unwrap();
    assert_eq!(unavailable["feerate"], json!(-1.0), "{unavailable}");
    assert!(
        unavailable["errors"]
            .to_string()
            .contains("mempool unavailable"),
        "{unavailable}"
    );
    let bad_th = dispatch(&ctx, "estimaterawfee", vec![json!(2), json!("fast")]).unwrap_err();
    assert!(
        rpc_message(&bad_th).contains("not of expected type number"),
        "{bad_th}"
    );
    let extra = dispatch(&ctx, "estimaterawfee", vec![json!(2), json!(0), json!(1)]).unwrap_err();
    assert_eq!(extra["code"], ERR_MISC, "{extra}");

    let (addr, _) = p2wpkh_regtest();
    let pk = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    for (output, needle) in [
        ("wpkh(/*)", "Ranged descriptor not accepted"),
        (
            "wpkh(tpubD6NzVbkrYhZ4/0h/1)",
            "Cannot derive script without private keys",
        ),
        ("not-an-address", "Invalid address or descriptor"),
    ] {
        let err = dispatch(
            &ctx,
            "generateblock",
            vec![json!(output), json!([]), json!(false)],
        )
        .unwrap_err();
        assert!(rpc_message(&err).contains(needle), "{output}: {err}");
    }
    let not_array = dispatch(&ctx, "generateblock", vec![json!(addr), json!("zz")]).unwrap_err();
    assert!(
        rpc_message(&not_array).contains("transactions must be an array"),
        "{not_array}"
    );
    let missing_tx = dispatch(&ctx, "generateblock", vec![json!(addr)]).unwrap_err();
    assert!(
        rpc_message(&missing_tx).contains("transactions required"),
        "{missing_tx}"
    );
    let unknown_txid = "11".repeat(32);
    let absent = dispatch(
        &ctx,
        "generateblock",
        vec![json!(addr), json!([unknown_txid])],
    )
    .unwrap_err();
    assert!(rpc_message(&absent).contains("not in mempool"), "{absent}");
    let junk_tx = dispatch(&ctx, "generateblock", vec![json!(addr), json!(["zz"])]).unwrap_err();
    assert!(
        rpc_message(&junk_tx).contains("Transaction decode failed"),
        "{junk_tx}"
    );
    for output in [
        format!("addr({addr})"),
        format!("combo({pk})"),
        format!("wsh(multi(1,{pk}))"),
    ] {
        let built = dispatch(
            &ctx,
            "generateblock",
            vec![json!(output), json!([]), json!(false)],
        )
        .unwrap();
        assert!(built["hex"].as_str().unwrap().len() > 160, "{built}");
    }
    let assembled = dispatch(
        &ctx,
        "generateblock",
        vec![json!(addr), json!([]), json!(false)],
    )
    .unwrap();
    let hex = assembled["hex"].as_str().unwrap().to_string();
    let proposed = dispatch(
        &bare,
        "getblocktemplate",
        vec![json!({"rules": ["segwit"], "mode": "proposal", "data": hex})],
    )
    .unwrap();
    assert!(
        proposed.is_null(),
        "a template built on this tip is a valid proposal: {proposed}"
    );
    let mut fat_cb: Block = deserialize(&rbitcoin_primitives::hex_decode(&hex).unwrap()).unwrap();
    let cb = &mut fat_cb.txdata[0].output[0].value;
    *cb = bitcoin::Amount::from_sat(cb.to_sat() + 1);
    fat_cb.header.merkle_root = fat_cb.compute_merkle_root().unwrap();
    let over_subsidy = dispatch(
        &ctx,
        "getblocktemplate",
        vec![json!({"rules": ["segwit"], "mode": "proposal", "data": serialize_hex(&fat_cb)})],
    )
    .unwrap();
    assert_eq!(over_subsidy, "bad-cb-amount", "{over_subsidy}");
    let mut block: Block = deserialize(&rbitcoin_primitives::hex_decode(&hex).unwrap()).unwrap();
    let original_bits = block.header.bits;
    let original_time = block.header.time;
    block.header.bits = CompactTarget::from_consensus(0x1d00ffff);
    let bad_bits = dispatch(
        &ctx,
        "getblocktemplate",
        vec![json!({"rules": ["segwit"], "mode": "proposal", "data": serialize_hex(&block)})],
    )
    .unwrap();
    assert_eq!(bad_bits, "bad-diffbits", "{bad_bits}");
    block.header.bits = original_bits;
    block.header.time = 0;
    let too_old = dispatch(
        &ctx,
        "getblocktemplate",
        vec![json!({"rules": ["segwit"], "mode": "proposal", "data": serialize_hex(&block)})],
    )
    .unwrap();
    assert_eq!(too_old, "time-too-old", "{too_old}");
    block.header.time = original_time.saturating_add(3 * 60 * 60);
    let too_new = dispatch(
        &ctx,
        "getblocktemplate",
        vec![json!({"rules": ["segwit"], "mode": "proposal", "data": serialize_hex(&block)})],
    )
    .unwrap();
    assert_eq!(too_new, "time-too-new", "{too_new}");
    let mut wrong_prev: Block =
        deserialize(&rbitcoin_primitives::hex_decode(&hex).unwrap()).unwrap();
    wrong_prev.header.prev_blockhash = bitcoin::BlockHash::from_byte_array([0xab; 32]);
    let not_tip = dispatch(
        &ctx,
        "getblocktemplate",
        vec![json!({"rules": ["segwit"], "mode": "proposal", "data": serialize_hex(&wrong_prev)})],
    )
    .unwrap();
    assert_eq!(not_tip, "inconclusive-not-best-prevblk", "{not_tip}");

    let bad_desc =
        dispatch(&ctx, "generatetodescriptor", vec![json!(1), json!("nope")]).unwrap_err();
    assert!(
        rpc_message(&bad_desc).contains("output must be an address or hex script"),
        "{bad_desc}"
    );
    for desc in [
        format!("addr({addr})"),
        format!("combo({pk})"),
        format!("wsh(multi(1,{pk}))"),
    ] {
        let mined = dispatch(&ctx, "generatetodescriptor", vec![json!(1), json!(desc)]).unwrap();
        assert_eq!(mined.as_array().unwrap().len(), 1, "{desc}: {mined}");
    }

    let mock_range = dispatch(&ctx, "setmocktime", vec![json!(1.5)]).unwrap_err();
    assert!(
        rpc_message(&mock_range).contains("timestamp must be an integer"),
        "{mock_range}"
    );

    dispatch(&ctx, "generate", vec![json!(100)]).unwrap();
    let cb = generated_coinbase_value(&ctx, 1);
    let (parent_hex, parent) = spend_coinbase_two_outputs(&ctx, 1, cb);
    let parent_id = dispatch(&ctx, "sendrawtransaction", vec![json!(parent_hex)]).unwrap();
    let child = loose_tx(
        2,
        0x21,
        OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        },
        400,
    );
    let child_hex = serialize_hex(&child);
    let child_id = dispatch(&ctx, "sendrawtransaction", vec![json!(child_hex)]).unwrap();
    let ancestors = dispatch(
        &ctx,
        "getmempoolancestors",
        vec![child_id.clone(), json!(true)],
    )
    .unwrap();
    assert!(
        ancestors.get(parent_id.as_str().unwrap()).is_some(),
        "{ancestors}"
    );
    let descendants = dispatch(
        &ctx,
        "getmempooldescendants",
        vec![parent_id.clone(), json!(true)],
    )
    .unwrap();
    assert!(
        descendants.get(child_id.as_str().unwrap()).is_some(),
        "{descendants}"
    );
    let missing_mem =
        dispatch(&ctx, "getmempoolancestors", vec![json!("22".repeat(32))]).unwrap_err();
    assert_eq!(rpc_message(&missing_mem), "Transaction not in mempool");
    let child_out = dispatch(&ctx, "gettxout", vec![child_id.clone(), json!(0)]).unwrap();
    assert_eq!(child_out["confirmations"], 0, "{child_out}");

    // Version 3 is admitted. 4 stays a version reject (missing inputs never run).
    let v3a = loose_tx(4, 0x31, marker_outpoint(0x31), 1);
    let v3b = loose_tx(4, 0x32, marker_outpoint(0x32), 1);
    let versions = dispatch(
        &ctx,
        "testmempoolaccept",
        vec![json!([serialize_hex(&v3a), serialize_hex(&v3b)])],
    )
    .unwrap();
    assert_eq!(versions[0]["reject-reason"], "version", "{versions}");
    assert_eq!(versions[1]["reject-reason"], "version", "{versions}");
    let conflict = loose_tx(2, 0x41, parent.input[0].previous_output, 1);
    let orphan = loose_tx(2, 0x42, marker_outpoint(0x42), 1);
    let rows = dispatch(
        &ctx,
        "testmempoolaccept",
        vec![json!([serialize_hex(&conflict), serialize_hex(&orphan)])],
    )
    .unwrap();
    assert_eq!(
        rows[0]["reject-reason"], "bip125-replacement-disallowed",
        "{rows}"
    );
    assert_eq!(rows[1]["reject-reason"], "missing-inputs", "{rows}");
    let fat = loose_tx(
        2,
        0x43,
        OutPoint {
            txid: parent.compute_txid(),
            vout: 1,
        },
        1,
    );
    let priced = dispatch(
        &ctx,
        "testmempoolaccept",
        vec![json!([serialize_hex(&fat), serialize_hex(&v3a)]), json!(1)],
    )
    .unwrap();
    assert_eq!(priced[0]["reject-reason"], "max-fee-exceeded", "{priced}");
    assert_eq!(priced[1]["reject-reason"], "version", "{priced}");

    let both = dispatch(&ctx, "getrawmempool", vec![json!(true), json!(true)]).unwrap_err();
    assert!(
        rpc_message(&both).contains("Verbose results cannot contain mempool sequence"),
        "{both}"
    );
    let short_txid = dispatch(
        &ctx,
        "prioritisetransaction",
        vec![json!("zz"), json!(0), json!(1)],
    )
    .unwrap_err();
    assert!(
        rpc_message(&short_txid).contains("txid must be of length 64"),
        "{short_txid}"
    );
    let bad_hex = dispatch(
        &ctx,
        "prioritisetransaction",
        vec![json!("gg".repeat(32)), json!(0), json!(1)],
    )
    .unwrap_err();
    assert!(rpc_message(&bad_hex).contains("hexadecimal"), "{bad_hex}");
    let dummy_type = dispatch(
        &ctx,
        "prioritisetransaction",
        vec![json!("11".repeat(32)), json!("nope"), json!(1)],
    )
    .unwrap_err();
    assert!(
        rpc_message(&dummy_type).contains("not of expected type number"),
        "{dummy_type}"
    );
    let dummy = dispatch(
        &ctx,
        "prioritisetransaction",
        vec![json!("11".repeat(32)), json!(1), json!(1)],
    )
    .unwrap_err();
    assert!(
        rpc_message(&dummy).contains("dummy argument to prioritisetransaction must be 0"),
        "{dummy}"
    );
    let fee_type = dispatch(
        &ctx,
        "prioritisetransaction",
        vec![json!("11".repeat(32)), json!(0), json!("1")],
    )
    .unwrap_err();
    assert!(
        rpc_message(&fee_type).contains("not of expected type number"),
        "{fee_type}"
    );

    let tip = hub.tip_header().unwrap();
    let height = hub.tip_height().unwrap();
    let sibling = rbitcoin_consensus::mine_regtest_paying(
        tip.prev_blockhash,
        tip.time + 50,
        height,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![],
    );
    let held = dispatch(&ctx, "submitblock", vec![json!(block_hex(&sibling))]).unwrap();
    assert_eq!(held, "inconclusive", "{held}");
    let held_hash = sibling.block_hash().to_string();
    let held_hdr = dispatch(&ctx, "getblockheader", vec![json!(held_hash), json!(true)]).unwrap();
    assert_eq!(held_hdr["confirmations"], -1, "{held_hdr}");
    assert_eq!(held_hdr["hash"], held_hash, "{held_hdr}");
    assert_eq!(held_hdr["nTx"], 1, "{held_hdr}");
    assert_eq!(
        held_hdr["previousblockhash"].as_str().unwrap(),
        tip.prev_blockhash.to_string(),
        "{held_hdr}"
    );
    assert!(held_hdr.get("nextblockhash").is_none(), "{held_hdr}");
    let mut held_keys = HEADER_KEYS_ACTIVE.to_vec();
    held_keys.push("previousblockhash");
    held_keys.sort_unstable();
    assert_eq!(object_keys(&held_hdr), held_keys, "{held_hdr}");
    let held_raw = dispatch(&ctx, "getblockheader", vec![json!(held_hash), json!(false)]).unwrap();
    assert_eq!(held_raw.as_str().unwrap().len(), 160, "{held_raw}");
    let held_body = dispatch(&ctx, "getblock", vec![json!(held_hash), json!(1)]).unwrap();
    assert_eq!(held_body["confirmations"], -1, "{held_body}");
    assert_eq!(held_body["tx"].as_array().unwrap().len(), 1, "{held_body}");
    let held_hex = dispatch(&ctx, "getblock", vec![json!(held_hash), json!(0)]).unwrap();
    assert!(held_hex.as_str().unwrap().len() > 160, "{held_hex}");

    let header_only = rbitcoin_consensus::mine_regtest_paying(
        hub.tip_hash().unwrap(),
        tip.time + 60,
        height + 1,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![],
    );
    dispatch(&ctx, "submitheader", vec![json!(block_hex(&header_only))]).unwrap();
    let off_hash = header_only.block_hash().to_string();
    let off = dispatch(&ctx, "getblockheader", vec![json!(off_hash), json!(true)]).unwrap();
    assert_eq!(off["confirmations"], -1, "{off}");
    assert!(off["height"].as_u64().is_some(), "{off}");
    assert!(off.get("nextblockhash").is_none(), "{off}");
    let mut off_keys = HEADER_KEYS_ACTIVE.to_vec();
    off_keys.push("previousblockhash");
    off_keys.sort_unstable();
    assert_eq!(object_keys(&off), off_keys, "{off}");
    let off_raw = dispatch(&ctx, "getblockheader", vec![json!(off_hash), json!(false)]).unwrap();
    assert_eq!(off_raw.as_str().unwrap().len(), 160, "{off_raw}");
    let undownloaded = dispatch(&ctx, "getblock", vec![json!(off_hash)]).unwrap_err();
    assert_eq!(
        rpc_message(&undownloaded),
        "Block not available (not fully downloaded)"
    );

    let stats_type = dispatch(&ctx, "getblockstats", vec![json!(1), json!({})]).unwrap_err();
    assert!(
        rpc_message(&stats_type).contains("expected array"),
        "{stats_type}"
    );
    let stats_hash = dispatch(&ctx, "getblockstats", vec![json!(true)]).unwrap_err();
    assert!(
        rpc_message(&stats_hash).contains("hash string or height"),
        "{stats_hash}"
    );
    ctx.query.set_block_filter_index(true).unwrap();
    let tip_filter = dispatch(
        &ctx,
        "getblockfilter",
        vec![json!(hub.tip_hash().unwrap().to_string())],
    )
    .unwrap_err();
    assert!(
        rpc_message(&tip_filter).contains("still in the process of being indexed"),
        "{tip_filter}"
    );
    let unknown_filter = dispatch(
        &ctx,
        "getblockfilter",
        vec![json!(off_hash), json!("unknown")],
    )
    .unwrap_err();
    assert!(
        rpc_message(&unknown_filter).contains("Unknown filtertype"),
        "{unknown_filter}"
    );

    for args in [json!("nope"), json!(null), json!(true), json!({})] {
        let echo_type = dispatch(&ctx, "echo", named(json!({"args": args}))).unwrap_err();
        assert!(
            rpc_message(&echo_type).contains("not of expected type array"),
            "{echo_type}"
        );
    }
    let echoed = dispatch(&ctx, "echo", named(json!({"args": [1]}))).unwrap();
    assert_eq!(echoed, json!([1]));

    let mut peers = ctx_without_chain(&ctx);
    peers.peers = Some(rbitcoin_net::PeerHub::new());
    let by_id = dispatch(&peers, "disconnectnode", vec![Value::Null, json!(7)]).unwrap_err();
    assert_eq!(rpc_message(&by_id), "Node not found in connected nodes");
    let by_addr = dispatch(&peers, "disconnectnode", vec![json!("127.0.0.1:18444")]).unwrap_err();
    assert_eq!(
        rpc_message(&by_addr),
        "Node not found in connected nodes",
        "{by_addr}"
    );
    let inbound = dispatch(
        &peers,
        "addconnection",
        vec![json!("127.0.0.1:18444"), json!("inbound")],
    )
    .unwrap_err();
    assert!(
        rpc_message(&inbound).contains("cannot create inbound"),
        "{inbound}"
    );
    let no_dialer = dispatch(
        &peers,
        "addconnection",
        vec![json!("127.0.0.1:18444"), json!("outbound-full-relay")],
    )
    .unwrap_err();
    assert!(
        rpc_message(&no_dialer).contains("no dialer attached"),
        "{no_dialer}"
    );

    let tip_hash = hub.tip_hash().unwrap().to_string();
    let (status, body) = rest_text(&ctx, "/rest/mempool/contents.hex", "");
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "{body}");
    assert!(body.contains("output format not found"), "{body}");
    let (status, body) = rest_text(&ctx, &format!("/rest/headers/0/{tip_hash}.json"), "");
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("Header count is invalid"), "{body}");
    let (status, body) = rest_text(&ctx, "/rest/getutxos/checkmempool.json", "");
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("empty request"), "{body}");
    let spec = format!("{}-0", "33".repeat(32));
    let many = (0..16).map(|_| spec.as_str()).collect::<Vec<_>>().join("/");
    let (status, body) = rest_text(&ctx, &format!("/rest/getutxos/{many}.json"), "");
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("max outpoints exceeded"), "{body}");
    let (status, body) = rest_text(&ctx, "/rest/mempool/contents.json", "verbose=maybe");
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("must be either"), "{body}");
    let (status, body) = rest_text(&ctx, &format!("/rest/tx/{}.json", "44".repeat(32)), "");
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "{body}");
    assert!(body.contains("not found"), "{body}");
    let (status, body) = rest_text(&ctx, "/rest/deploymentinfo.hex", "");
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "{body}");
    assert!(body.contains("output format not found"), "{body}");
    let (status, body) = rest_text(&ctx, "/rest/blockfilter/basic.json", "");
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("Invalid URI format"), "{body}");
    let (status, body) = rest_text(
        &ctx,
        &format!("/rest/blockfilter/basic/{tip_hash}.json"),
        "",
    );
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "{body}");
    assert!(
        body.contains("still in the process of being indexed"),
        "{body}"
    );
    let (status, body) = rest_text(&ctx, "/rest/blockhashbyheight/nope.json", "");
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = rest_text(&ctx, "/rest/blockhashbyheight/999999.json", "");
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "{body}");
    assert!(body.contains("out of range"), "{body}");

    let genesis = dispatch(&ctx, "getblockhash", vec![json!(0)])
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = rest_text(&ctx, &format!("/rest/headers/2/{genesis}.json"), "");
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body.contains(&genesis), "{body}");
    let (status, body) = rest_text(&ctx, &format!("/rest/headers/2/{genesis}.hex"), "");
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body.trim().len(), 320, "{body}");
    let headers_bin = dispatch_rest(&ctx, &format!("/rest/headers/2/{genesis}.bin"), "", &[]);
    assert_eq!(headers_bin.status, axum::http::StatusCode::OK);
    assert_eq!(headers_bin.body.len(), 160);
    let (status, body) = rest_text(
        &ctx,
        &format!("/rest/headers/1/{}.json", "ab".repeat(32)),
        "",
    );
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("Invalid hash"), "{body}");

    let (status, body) = rest_text(&ctx, &format!("/rest/block/{tip_hash}.json"), "");
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body.contains("\"tx\""), "{body}");
    let (status, body) = rest_text(
        &ctx,
        &format!("/rest/block/notxdetails/{tip_hash}.json"),
        "",
    );
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body.contains("\"tx\""), "{body}");
    let (status, body) = rest_text(&ctx, &format!("/rest/block/{tip_hash}.hex"), "");
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body.trim().len() > 160, "{body}");
    let block_bin = dispatch_rest(&ctx, &format!("/rest/block/{tip_hash}.bin"), "", &[]);
    assert_eq!(block_bin.status, axum::http::StatusCode::OK);
    assert!(block_bin.body.len() > 80, "{}", block_bin.body.len());
    let (status, body) = rest_text(&ctx, &format!("/rest/block/{}.bin", "ab".repeat(32)), "");
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "{body}");

    let child_txid = child_id.as_str().unwrap();
    let (status, body) = rest_text(&ctx, &format!("/rest/tx/{child_txid}.hex"), "");
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body.trim().len() > 20, "{body}");
    let tx_bin = dispatch_rest(&ctx, &format!("/rest/tx/{child_txid}.bin"), "", &[]);
    assert_eq!(tx_bin.status, axum::http::StatusCode::OK);
    assert!(!tx_bin.body.is_empty());

    let height2 = dispatch(&ctx, "getblockhash", vec![json!(2)]).unwrap();
    let coinbase = dispatch(&ctx, "getblock", vec![height2, json!(1)]).unwrap();
    let coinbase_txid = coinbase["tx"][0].as_str().unwrap();
    let (status, body) = rest_text(&ctx, &format!("/rest/getutxos/{coinbase_txid}-0.json"), "");
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body.contains("\"bitmap\":\"1\""), "{body}");
    let (status, body) = rest_text(
        &ctx,
        &format!("/rest/getutxos/checkmempool/{child_txid}-0.json"),
        "",
    );
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body.contains("\"bitmap\":\"1\""), "{body}");
    assert!(body.contains("2147483647"), "{body}");
    let (status, body) = rest_text(&ctx, &format!("/rest/getutxos/{coinbase_txid}-1.json"), "");
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body.contains("\"bitmap\":\"0\""), "{body}");
    let (status, body) = rest_text(
        &ctx,
        &format!("/rest/getutxos/{}-0.json", "00".repeat(32)),
        "",
    );
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body.contains("\"bitmap\":\"0\""), "{body}");
    let (status, body) = rest_text(&ctx, "/rest/getutxos/checkmempool.bin", "");
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "{body}");

    let (status, body) = rest_text(&ctx, "/rest/mempool/info.json", "");
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body.contains("\"size\""), "{body}");
    let (status, body) = rest_text(
        &ctx,
        "/rest/mempool/contents.json",
        "verbose=false&mempool_sequence=true",
    );
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body.contains(child_txid), "{body}");
    let (status, body) = rest_text(&ctx, "/rest/mempool/nope.json", "");
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");

    let (status, body) = rest_text(&ctx, "/rest/blockhashbyheight/1.hex", "");
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body.trim().len(), 64, "{body}");
    let hash_bin = dispatch_rest(&ctx, "/rest/blockhashbyheight/1.bin", "", &[]);
    assert_eq!(hash_bin.status, axum::http::StatusCode::OK);
    assert_eq!(hash_bin.body.len(), 32);

    let (status, body) = rest_text(&ctx, "/rest/chaininfo", "");
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "{body}");
    assert!(body.contains("output format not found"), "{body}");
    let (status, body) = rest_text(&ctx, &format!("/rest/deploymentinfo/{tip_hash}.json"), "");
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let (status, body) = rest_text(&ctx, "/rest/nope.json", "");
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "{body}");

    let _ = std::fs::remove_dir_all(&dir);
}

fn rest_text(ctx: &RpcContext, path: &str, query: &str) -> (axum::http::StatusCode, String) {
    let reply = dispatch_rest(ctx, path, query, &[]);
    (
        reply.status,
        String::from_utf8_lossy(&reply.body).into_owned(),
    )
}

fn spend_coinbase_two_outputs(ctx: &RpcContext, height: u32, value: u64) -> (String, Transaction) {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{OutPoint, Sequence, TxIn, TxOut, Witness};
    let hash = dispatch(ctx, "getblockhash", vec![json!(height)]).unwrap();
    let blk = dispatch(ctx, "getblock", vec![hash, json!(2)]).unwrap();
    let cb_txid = blk["tx"][0]["txid"].as_str().unwrap();
    let script = ScriptBuf::from_bytes(vec![0x51]);
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
                value: Amount::from_sat(1_000),
                script_pubkey: script.clone(),
            },
            TxOut {
                value: Amount::from_sat(value - 1_000 - 500),
                script_pubkey: script,
            },
        ],
    };
    (rbitcoin_primitives::hex_encode(serialize(&spend)), spend)
}

include!("../regtest_chain_ops_journey.rs");

mod chain;
mod mempool;
