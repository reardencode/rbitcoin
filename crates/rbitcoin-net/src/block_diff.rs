//! Height-1 differential vs Core `submitblock`. Not a node RPC.

use crate::chain::{AcceptOutcome, ChainHub};
use crate::error::NetError;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, OutPoint, ScriptBuf};
use rbitcoin_consensus::{
    genesis_block, prepare_regtest_candidate, ChainParams, REGTEST_BLOCK_SPACING,
};
use rbitcoin_primitives::hex_encode;
use std::path::Path;
use std::time::{Duration, Instant};

const CORE_SKIP: &[&str] = &[
    "bad-prevblk",
    "prev-blk-not-found",
    "inconclusive",
    "duplicate",
    "duplicate-invalid",
    "duplicate-inconclusive",
];

const CORE_DESYNC_SKIP: &[&str] = &["inconclusive", "bad-prevblk", "prev-blk-not-found"];
const CORE_DUPLICATE_SKIP: &[&str] = &["duplicate", "duplicate-invalid", "duplicate-inconclusive"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffVerdict {
    Accept,
    Reject,
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleReply {
    NullAccept,
    Reason(String),
    RpcError,
    Dead,
}

pub trait BlockOracle {
    fn submitblock_hex(&self, hex: &str) -> OracleReply;
    fn liveness_ok(&self) -> bool;
    fn core_rewind_to_genesis(&self) -> Result<(), &'static str>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffTip {
    pub hash: BlockHash,
    pub time: u32,
    pub height: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompareOne {
    NotABlock,
    Skipped,
    Agreed { accept: bool },
    Disagreed { ours: bool, core: bool, hex: String },
    Harness(&'static str),
}

pub fn diff_regtest_params() -> ChainParams {
    let mut params = ChainParams::regtest();
    params
        .apply_test_activation_height("bip34", 1)
        .expect("regtest overlay");
    params
}

pub fn genesis_diff_tip(params: &ChainParams) -> DiffTip {
    let g = genesis_block(params);
    DiffTip {
        hash: g.block_hash(),
        time: g.header.time,
        height: 0,
    }
}

pub fn is_core_connectivity_skip(reason: &str) -> bool {
    CORE_SKIP.contains(&reason)
}

pub fn verdict_from_core_reply(reply: &OracleReply) -> DiffVerdict {
    match reply {
        OracleReply::NullAccept => DiffVerdict::Accept,
        OracleReply::Reason(r) if is_core_connectivity_skip(r) => DiffVerdict::Skip,
        OracleReply::Reason(_) => DiffVerdict::Reject,
        OracleReply::RpcError => DiffVerdict::Skip,
        OracleReply::Dead => DiffVerdict::Skip,
    }
}

pub fn verdict_from_accept(
    r: Result<AcceptOutcome, NetError>,
) -> Result<DiffVerdict, &'static str> {
    match r {
        Ok(AcceptOutcome::Accepted { .. }) => Ok(DiffVerdict::Accept),
        Ok(AcceptOutcome::AlreadyHave | AcceptOutcome::IgnoredWeaker) => Ok(DiffVerdict::Skip),
        Err(NetError::Protocol(_) | NetError::Consensus(_)) => Ok(DiffVerdict::Reject),
        Err(NetError::Io(_) | NetError::Timeout | NetError::Disconnected) => Err("harness"),
        Err(_) => Err("harness"),
    }
}

pub fn parse_submitblock_json(body: &str) -> Result<Option<String>, &'static str> {
    let body = body.trim();
    if json_field_is_error_object(body) {
        return Err("rpc error");
    }
    match json_result_token(body) {
        Some(JsonTok::Null) => Ok(None),
        Some(JsonTok::String(s)) => Ok(Some(s)),
        _ => Err("malformed"),
    }
}

enum JsonTok {
    Null,
    String(String),
}

fn json_result_token(body: &str) -> Option<JsonTok> {
    let rest = after_key(body, "result")?;
    if rest.starts_with("null") {
        return Some(JsonTok::Null);
    }
    if rest.starts_with('"') {
        return Some(JsonTok::String(json_quoted(rest)?));
    }
    None
}

fn json_field_is_error_object(body: &str) -> bool {
    match after_key(body, "error") {
        Some(rest) => rest.starts_with('{'),
        None => false,
    }
}

fn after_key<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\"");
    let i = body.find(&needle)?;
    let rest = body[i + needle.len()..].trim_start();
    rest.strip_prefix(':').map(str::trim_start)
}

fn json_quoted(rest: &str) -> Option<String> {
    let b = rest.as_bytes();
    if b.first() != Some(&b'"') {
        return None;
    }
    let mut out = String::new();
    let mut i = 1;
    while i < b.len() {
        match b[i] {
            b'"' => return Some(out),
            b'\\' if i + 1 < b.len() => {
                out.push(b[i + 1] as char);
                i += 2;
            }
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    None
}

pub fn check_diff_env(head: Option<&str>, io: Option<&str>) -> Result<(), &'static str> {
    match head {
        Some("tiny" | "test" | "small") => {}
        Some(_) => return Err("RBITCOIN_HEAD_SCALE"),
        None => return Err("RBITCOIN_HEAD_SCALE"),
    }
    match io {
        Some("fd" | "pread" | "libc" | "pwrite") => Ok(()),
        _ => Err("RBITCOIN_IO"),
    }
}

pub fn wait_for_file(path: &Path, deadline: Instant) -> Result<(), &'static str> {
    while Instant::now() < deadline {
        if path.is_file() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if path.is_file() {
        Ok(())
    } else {
        Err("timeout")
    }
}

pub fn split_http_body(raw: &[u8]) -> Result<&[u8], &'static str> {
    const SEP: &[u8] = b"\r\n\r\n";
    let Some(i) = raw.windows(SEP.len()).position(|w| w == SEP) else {
        return Err("no header separator");
    };
    Ok(&raw[i + SEP.len()..])
}

pub fn basic_auth_b64(user: &str, pass: &str) -> String {
    base64_encode(format!("{user}:{pass}").as_bytes())
}

pub fn build_jsonrpc_http_request(
    host: &str,
    auth_b64: &str,
    method: &str,
    params_json: &str,
) -> Vec<u8> {
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params_json}}}"#);
    let mut out = format!(
        "POST / HTTP/1.1\r\nHost: {host}\r\nAuthorization: Basic {auth_b64}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

fn base64_encode(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i];
        let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };
        out.push(T[(b0 >> 2) as usize] as char);
        out.push(T[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if i + 1 < data.len() {
            out.push(T[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < data.len() {
            out.push(T[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

pub fn compare_one(
    hub: &ChainHub,
    tip: &mut DiffTip,
    oracle: &dyn BlockOracle,
    data: &[u8],
) -> CompareOne {
    let Ok(mut block) = deserialize::<Block>(data) else {
        return CompareOne::NotABlock;
    };
    if block.txdata.is_empty() {
        return CompareOne::NotABlock;
    }
    let old = tip.clone();
    prepare_regtest_candidate(
        &mut block,
        old.hash,
        old.time.saturating_add(REGTEST_BLOCK_SPACING),
    );
    let hex = hex_encode(serialize(&block));
    let ours_res = hub.accept_received_block(block);
    let ours = match verdict_from_accept(ours_res) {
        Ok(v) => v,
        Err(msg) => return CompareOne::Harness(msg),
    };
    let reply = oracle.submitblock_hex(&hex);
    if matches!(reply, OracleReply::Dead)
        || (matches!(reply, OracleReply::RpcError) && !oracle.liveness_ok())
    {
        if ours == DiffVerdict::Accept {
            let _ = hub.rewind_to_height(0);
        }
        let _ = oracle.core_rewind_to_genesis();
        return CompareOne::Harness("oracle dead");
    }
    let core = verdict_from_core_reply(&reply);
    combine(hub, oracle, ours, core, &reply, &hex)
}

fn combine(
    hub: &ChainHub,
    oracle: &dyn BlockOracle,
    ours: DiffVerdict,
    core: DiffVerdict,
    reply: &OracleReply,
    hex: &str,
) -> CompareOne {
    let reason = match reply {
        OracleReply::Reason(s) => s.as_str(),
        _ => "",
    };
    match (ours, core) {
        (DiffVerdict::Accept, DiffVerdict::Accept) => rewind_agreed(hub, oracle, true),
        (DiffVerdict::Accept, DiffVerdict::Skip) if CORE_DUPLICATE_SKIP.contains(&reason) => {
            rewind_agreed(hub, oracle, true)
        }
        (DiffVerdict::Accept, DiffVerdict::Skip) if CORE_DESYNC_SKIP.contains(&reason) => {
            let _ = hub.rewind_to_height(0);
            let _ = oracle.core_rewind_to_genesis();
            CompareOne::Harness("core not at genesis")
        }
        (DiffVerdict::Accept, DiffVerdict::Reject) => CompareOne::Disagreed {
            ours: true,
            core: false,
            hex: hex.to_string(),
        },
        (DiffVerdict::Reject, DiffVerdict::Reject) => CompareOne::Agreed { accept: false },
        (DiffVerdict::Reject, DiffVerdict::Accept) => CompareOne::Disagreed {
            ours: false,
            core: true,
            hex: hex.to_string(),
        },
        (DiffVerdict::Reject, DiffVerdict::Skip) => CompareOne::Skipped,
        (DiffVerdict::Skip, DiffVerdict::Accept) => {
            let _ = oracle.core_rewind_to_genesis();
            CompareOne::Harness("skip+accept")
        }
        (DiffVerdict::Skip, DiffVerdict::Reject | DiffVerdict::Skip) => CompareOne::Skipped,
        (DiffVerdict::Accept, DiffVerdict::Skip) => {
            let _ = hub.rewind_to_height(0);
            CompareOne::Skipped
        }
    }
}

fn rewind_agreed(hub: &ChainHub, oracle: &dyn BlockOracle, accept: bool) -> CompareOne {
    if hub.rewind_to_height(0).is_err() {
        return CompareOne::Harness("rewind failed");
    }
    if oracle.core_rewind_to_genesis().is_err() {
        return CompareOne::Harness("core rewind failed");
    }
    CompareOne::Agreed { accept }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbitcoin_consensus::{mine_empty_regtest, mine_regtest_paying, Milestone};
    use rbitcoin_query::Query;
    use std::cell::Cell;
    use std::fs;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct MockOracle {
        reply: OracleReply,
        rewind: Cell<u32>,
        live: bool,
    }

    impl MockOracle {
        fn new(reply: OracleReply) -> Self {
            Self {
                reply,
                rewind: Cell::new(0),
                live: true,
            }
        }
    }

    impl BlockOracle for MockOracle {
        fn submitblock_hex(&self, _hex: &str) -> OracleReply {
            self.reply.clone()
        }
        fn liveness_ok(&self) -> bool {
            self.live
        }
        fn core_rewind_to_genesis(&self) -> Result<(), &'static str> {
            self.rewind.set(self.rewind.get() + 1);
            Ok(())
        }
    }

    fn tmp_diff_hub() -> (std::path::PathBuf, ChainHub, DiffTip) {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        static LOCK: Mutex<()> = Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "rbtc-diff-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::create_dir_all(&dir);
        let q = Query::open_or_create(dir.join("store")).expect("open");
        let params = diff_regtest_params();
        let hub = ChainHub::new(q, params.clone(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let tip = genesis_diff_tip(&params);
        (dir, hub, tip)
    }

    fn height1_bytes() -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../rbitcoin-consensus/tests/fixtures/regtest_height1.bin");
        fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    }

    fn different_height1() -> Vec<u8> {
        let params = diff_regtest_params();
        let g = genesis_block(&params);
        let spk = ScriptBuf::from_bytes(vec![0x51, 0x51]);
        let b = mine_regtest_paying(
            g.block_hash(),
            g.header.time + REGTEST_BLOCK_SPACING,
            1,
            spk,
            vec![],
        );
        serialize(&b)
    }

    #[test]
    fn parse_submitblock_json_table() {
        assert_eq!(
            parse_submitblock_json(r#"{"result":null,"error":null,"id":1}"#).unwrap(),
            None
        );
        assert_eq!(
            parse_submitblock_json(r#"{"result":"inconclusive","error":null,"id":1}"#)
                .unwrap()
                .as_deref(),
            Some("inconclusive")
        );
        assert_eq!(
            parse_submitblock_json(r#"{"result":"duplicate","error":null}"#)
                .unwrap()
                .as_deref(),
            Some("duplicate")
        );
        assert_eq!(
            parse_submitblock_json(r#"{"result":"duplicate-invalid","error":null}"#)
                .unwrap()
                .as_deref(),
            Some("duplicate-invalid")
        );
        assert_eq!(
            parse_submitblock_json(r#"{"result":"bad-txnmrklroot","error":null}"#)
                .unwrap()
                .as_deref(),
            Some("bad-txnmrklroot")
        );
        assert_eq!(
            parse_submitblock_json(r#"{"result":null,"error":{"code":-1,"message":"x"}}"#)
                .unwrap_err(),
            "rpc error"
        );
        assert_eq!(parse_submitblock_json("not json").unwrap_err(), "malformed");
    }

    #[test]
    fn is_core_connectivity_skip_exact() {
        assert!(is_core_connectivity_skip("duplicate"));
        assert!(is_core_connectivity_skip("duplicate-invalid"));
        assert!(!is_core_connectivity_skip("duplicated"));
        assert!(!is_core_connectivity_skip("bad-txnmrklroot"));
        assert_eq!(
            verdict_from_core_reply(&OracleReply::NullAccept),
            DiffVerdict::Accept
        );
        assert_eq!(
            verdict_from_core_reply(&OracleReply::Reason("inconclusive".into())),
            DiffVerdict::Skip
        );
        assert_eq!(
            verdict_from_core_reply(&OracleReply::Reason("bad-txnmrklroot".into())),
            DiffVerdict::Reject
        );
    }

    #[test]
    fn verdict_from_accept_table() {
        assert_eq!(
            verdict_from_accept(Ok(AcceptOutcome::Accepted { height: 1 })).unwrap(),
            DiffVerdict::Accept
        );
        assert_eq!(
            verdict_from_accept(Ok(AcceptOutcome::AlreadyHave)).unwrap(),
            DiffVerdict::Skip
        );
        assert_eq!(
            verdict_from_accept(Ok(AcceptOutcome::IgnoredWeaker)).unwrap(),
            DiffVerdict::Skip
        );
        assert_eq!(
            verdict_from_accept(Err(NetError::Protocol("non-genesis without tip"))).unwrap(),
            DiffVerdict::Reject
        );
        assert_eq!(
            verdict_from_accept(Err(NetError::Consensus("bad-txnmrklroot".into()))).unwrap(),
            DiffVerdict::Reject
        );
        assert!(verdict_from_accept(Err(NetError::Io(std::io::Error::other("x")))).is_err());
    }

    #[test]
    fn accept_received_block_random_prev_is_skip() {
        let (dir, hub, _tip) = tmp_diff_hub();
        let params = diff_regtest_params();
        let g = genesis_block(&params);
        let mut b = mine_empty_regtest(g.block_hash(), g.header.time + 600, 1);
        b.header.prev_blockhash = BlockHash::from_byte_array([0x11; 32]);
        rbitcoin_consensus::grind_regtest_pow(&mut b.header);
        let r = hub.accept_received_block(b);
        assert!(matches!(r, Ok(AcceptOutcome::IgnoredWeaker)));
        assert_eq!(verdict_from_accept(r).unwrap(), DiffVerdict::Skip);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn compare_one_height1_journey() {
        let (dir, hub, mut tip) = tmp_diff_hub();
        let raw = height1_bytes();

        let mock = MockOracle::new(OracleReply::NullAccept);
        match compare_one(&hub, &mut tip, &mock, &raw) {
            CompareOne::Agreed { accept: true } => {}
            other => panic!("expected agreed accept, got {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(0));
        assert!(mock.rewind.get() >= 1);

        let mock = MockOracle::new(OracleReply::Reason("inconclusive".into()));
        match compare_one(&hub, &mut tip, &mock, &raw) {
            CompareOne::Harness(_) => {}
            other => panic!("expected harness, got {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(0));
        assert!(mock.rewind.get() >= 1);

        for s in ["bad-prevblk", "prev-blk-not-found"] {
            let mock = MockOracle::new(OracleReply::Reason(s.into()));
            match compare_one(&hub, &mut tip, &mock, &raw) {
                CompareOne::Harness(_) => {}
                other => panic!("{s}: {other:?}"),
            }
        }

        let mock = MockOracle::new(OracleReply::Reason("duplicate".into()));
        match compare_one(&hub, &mut tip, &mock, &raw) {
            CompareOne::Agreed { accept: true } => {}
            other => panic!("duplicate: {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(0));

        assert!(matches!(
            compare_one(&hub, &mut tip, &mock, b"junk"),
            CompareOne::NotABlock
        ));

        let mock = MockOracle::new(OracleReply::Reason("bad-txnmrklroot".into()));
        match compare_one(&hub, &mut tip, &mock, &raw) {
            CompareOne::Disagreed {
                ours: true,
                core: false,
                ..
            } => {}
            other => panic!("disagree: {other:?}"),
        }
        hub.rewind_to_height(0).unwrap();

        let mut bad: Block = deserialize(&raw).unwrap();
        bad.txdata[0].input[0].previous_output = OutPoint {
            txid: bitcoin::Txid::from_byte_array([1u8; 32]),
            vout: 0,
        };
        let mock = MockOracle::new(OracleReply::Reason("bad-cb-missing".into()));
        match compare_one(&hub, &mut tip, &mock, &serialize(&bad)) {
            CompareOne::Agreed { accept: false } => {}
            other => panic!("non-coinbase: {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(0));

        let mock = MockOracle {
            reply: OracleReply::Dead,
            rewind: Cell::new(0),
            live: false,
        };
        match compare_one(&hub, &mut tip, &mock, &raw) {
            CompareOne::Harness(_) => {}
            other => panic!("dead: {other:?}"),
        }

        let first: Block = deserialize(&raw).unwrap();
        hub.accept_received_block(first).unwrap();
        assert_eq!(hub.tip_height(), Some(1));
        let mock = MockOracle::new(OracleReply::NullAccept);
        match compare_one(&hub, &mut tip, &mock, &different_height1()) {
            CompareOne::Harness(_) => {}
            other => panic!("skip+accept: {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(1));
        assert!(mock.rewind.get() >= 1);
        let _ = fs::remove_dir_all(dir);

        let (dir, hub, mut tip) = tmp_diff_hub();
        let params = diff_regtest_params();
        let g = genesis_block(&params);
        let mut held = mine_empty_regtest(g.block_hash(), g.header.time + 600, 1);
        held.header.prev_blockhash = BlockHash::from_byte_array([0x22; 32]);
        rbitcoin_consensus::grind_regtest_pow(&mut held.header);
        let _ = hub.accept_received_block(held);
        let mock = MockOracle::new(OracleReply::NullAccept);
        match compare_one(&hub, &mut tip, &mock, &raw) {
            CompareOne::Agreed { accept: true } => {}
            other => panic!("hold then accept: {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(0));

        let mut no_bip34: Block = deserialize(&raw).unwrap();
        no_bip34.txdata[0].input[0].script_sig = ScriptBuf::from_bytes(vec![0x00, 0x00]);
        let mock = MockOracle::new(OracleReply::Reason("bad-cb-height".into()));
        match compare_one(&hub, &mut tip, &mock, &serialize(&no_bip34)) {
            CompareOne::Agreed { accept: false } => {}
            other => panic!("bip34: {other:?}"),
        }

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn wait_for_file_ok_and_timeout() {
        let dir = std::env::temp_dir().join(format!(
            "rbtc-wait-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("cookie");
        let p2 = p.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            fs::write(p2, b"x").unwrap();
        });
        wait_for_file(&p, Instant::now() + Duration::from_secs(2)).unwrap();
        let missing = dir.join("nope");
        assert_eq!(
            wait_for_file(&missing, Instant::now() + Duration::from_millis(20)).unwrap_err(),
            "timeout"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn split_http_body_and_request() {
        let req = build_jsonrpc_http_request("127.0.0.1:1", "abc", "submitblock", r#"["00"]"#);
        let s = String::from_utf8(req.clone()).unwrap();
        assert!(s.contains("POST / HTTP/1.1"));
        assert!(s.contains("Authorization: Basic abc"));
        assert!(s.contains(r#""method":"submitblock""#));
        let body = split_http_body(&req).unwrap();
        assert!(std::str::from_utf8(body).unwrap().contains("submitblock"));
        assert!(split_http_body(b"nope").is_err());
    }

    #[test]
    fn check_diff_env_table() {
        assert!(check_diff_env(None, Some("fd")).is_err());
        assert!(check_diff_env(Some("mainnet"), Some("fd")).is_err());
        assert!(check_diff_env(Some("tiny"), Some("uring")).is_err());
        assert!(check_diff_env(Some("tiny"), Some("fd")).is_ok());
        assert!(check_diff_env(Some("test"), Some("pread")).is_ok());
        assert!(check_diff_env(Some("small"), Some("libc")).is_ok());
        assert!(check_diff_env(Some("tiny"), Some("pwrite")).is_ok());
    }

    #[test]
    fn basic_auth_b64_known() {
        assert_eq!(basic_auth_b64("user", "pass"), "dXNlcjpwYXNz");
    }
}
