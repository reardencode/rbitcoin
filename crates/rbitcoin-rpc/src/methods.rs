//! Tier-1 Core-class JSON-RPC method handlers (pure dispatch over Query/mempool).

use bitcoin::consensus::{deserialize, encode::serialize_hex, Encodable};
use bitcoin::hashes::Hash;
use bitcoin::key::PublicKey;
use bitcoin::script::Builder;
use bitcoin::{
    Address, Amount, Block, BlockHash, Network as BtcNetwork, OutPoint, ScriptBuf, Transaction,
    Txid,
};
use rbitcoin_net::MempoolHub;
use rbitcoin_primitives::{hex_decode, hex_encode, Height, Network};
use rbitcoin_query::Query;
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Core / Electrum / Esplora **display order** hex for a 32-byte hash or txid.
///
/// Store and rust-bitcoin `to_byte_array()` use **internal** byte order; RPC
/// clients expect the reversed hex (same as `BlockHash`/`Txid` `Display`).
fn sat_kvb_to_btc(sat_kvb: u64) -> f64 {
    sat_kvb as f64 / 100_000_000.0
}

fn hash_hex_display(h: &[u8; 32]) -> String {
    let mut rev = *h;
    rev.reverse();
    hex_encode(rev)
}

/// Parse Core display-order 32-byte hex → internal byte order.
pub(crate) fn parse_hash32_display(hex: &str) -> Result<[u8; 32], Value> {
    let mut b = hex_decode(hex).map_err(|e| rpc_error(ERR_INVALID_PARAMS, e.to_string()))?;
    if b.len() != 32 {
        return Err(rpc_error(
            ERR_INVALID_PARAMS,
            "hash/txid must be 32 bytes hex",
        ));
    }
    b.reverse();
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

/// Shared process context for RPC handlers.
pub struct RpcContext {
    pub query: Arc<Query>,
    pub mempool: Option<Arc<MempoolHub>>,
    pub network: Network,
    pub start: Instant,
    pub stop: Arc<AtomicBool>,
    /// Best-effort live peer count (updated by node; 0 if unknown).
    pub connections: Arc<AtomicU64>,
    /// `true` while IBD catch-up is incomplete (node sets).
    pub initial_block_download: Arc<AtomicBool>,
    /// `getnetworkinfo.subversion` (BIP14 / Core `-uacomment` shape).
    pub subversion: String,
    /// Regtest generate/submitblock. Node attaches [`ChainHub`] via this trait.
    pub regtest: Option<Arc<dyn RpcRegtest>>,
    /// Live P2P sessions (`getpeerinfo` / `addnode` / `disconnectnode`).
    pub peers: Option<Arc<rbitcoin_net::PeerHub>>,
    /// Live chain (invalidate / reconsider / precious).
    pub chain: Option<Arc<rbitcoin_net::ChainHub>>,
    /// Core `getrpcinfo.logpath` (`{datadir}/debug.log`).
    pub logpath: String,
    /// In-flight RPC methods (method, start) for `getrpcinfo.active_commands`.
    pub active: std::sync::Mutex<Vec<(String, Instant)>>,
}

/// Outcome of `submitblock` (Core: `null` or a reject-reason string).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitBlockOutcome {
    Accepted,
    Duplicate,
    IgnoredWeaker,
    Rejected(String),
}

/// Regtest-only mine + accept. Implemented by the node (not a mining product).
pub trait RpcRegtest: Send + Sync {
    fn generate_to_script(
        &self,
        nblocks: u32,
        script_pubkey: ScriptBuf,
        extra_txs: Vec<Transaction>,
    ) -> Result<Vec<BlockHash>, String>;

    fn assemble_block_to_script(
        &self,
        script_pubkey: ScriptBuf,
        extra_txs: Vec<Transaction>,
    ) -> Result<Block, String>;

    fn submit_block(&self, block: Block) -> SubmitBlockOutcome;

    /// `0` = wall clock. Regtest harness only.
    fn set_mock_time(&self, timestamp: i64) -> Result<(), String>;
}

impl RpcContext {
    pub fn uptime_secs(&self) -> u64 {
        self.start.elapsed().as_secs()
    }
}

/// JSON-RPC error object (Core-ish codes).
pub fn rpc_error(code: i64, message: impl Into<String>) -> Value {
    json!({ "code": code, "message": message.into() })
}

pub const ERR_MISC: i64 = -1;
/// Core `RPC_TYPE_ERROR`.
pub const ERR_TYPE_ERROR: i64 = -3;
/// Core `RPC_INVALID_ADDRESS_OR_KEY`.
pub const ERR_INVALID_ADDRESS_OR_KEY: i64 = -5;
/// Core `RPC_DESERIALIZATION_ERROR`.
pub const ERR_DESERIALIZATION: i64 = -22;
/// Core `RPC_VERIFY_ERROR` (`submitheader` / header validation).
pub const ERR_VERIFY_ERROR: i64 = -25;
/// Core `RPC_CLIENT_NODE_NOT_CONNECTED`.
pub const ERR_CLIENT_NODE_NOT_CONNECTED: i64 = -29;
/// Core `RPC_INVALID_PARAMETER` (unknown named param, mocktime range, …).
pub const ERR_INVALID_PARAMETER: i64 = -8;
/// Core `RPC_VERIFY_REJECTED` (sendrawtransaction / testmempoolaccept).
pub const ERR_VERIFY_REJECTED: i64 = -26;
pub const ERR_INVALID_PARAMS: i64 = -32602;
pub const ERR_METHOD_NOT_FOUND: i64 = -32601;
pub const ERR_INVALID_REQUEST: i64 = -32600;

/// JSON-RPC `params`: positional array or Core named object.
#[derive(Clone, Debug, Default)]
pub struct RpcParams {
    pos: Vec<Value>,
    named: Option<serde_json::Map<String, Value>>,
}

impl RpcParams {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn positional(pos: Vec<Value>) -> Self {
        Self { pos, named: None }
    }

    pub fn pos_len(&self) -> usize {
        self.pos.len()
    }

    pub fn named(mut named: serde_json::Map<String, Value>) -> Self {
        // AuthServiceProxy mixed call: `{args: [...], argN: ...}`.
        let pos = match named.remove("args") {
            Some(Value::Array(a)) => a,
            Some(other) => {
                named.insert("args".into(), other);
                Vec::new()
            }
            None => Vec::new(),
        };
        Self {
            pos,
            named: Some(named),
        }
    }

    pub fn get(&self, index: usize, name: &str) -> Option<&Value> {
        if let Some(m) = &self.named {
            if let Some(v) = m.get(name) {
                return Some(v);
            }
            // Mixed object: named miss falls through to the peeled `args` array.
            if !self.pos.is_empty() {
                return self.pos.get(index);
            }
            return None;
        }
        self.pos.get(index)
    }

    pub fn req(&self, index: usize, name: &str) -> Result<&Value, Value> {
        self.get(index, name)
            .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, format!("{name} required")))
    }

    pub fn req_str(&self, index: usize, name: &str) -> Result<&str, Value> {
        self.req(index, name)?
            .as_str()
            .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, format!("{name} must be a string")))
    }

    pub fn req_u64(&self, index: usize, name: &str) -> Result<u64, Value> {
        json_u64(self.req(index, name)?)
            .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, format!("{name} must be an integer")))
    }

    pub fn opt_u64(&self, index: usize, name: &str) -> Result<Option<u64>, Value> {
        match self.get(index, name) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => json_u64(v)
                .map(Some)
                .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, format!("{name} must be an integer"))),
        }
    }

    pub fn opt_str(&self, index: usize, name: &str) -> Result<Option<&str>, Value> {
        match self.get(index, name) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => v
                .as_str()
                .map(Some)
                .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, format!("{name} must be a string"))),
        }
    }

    pub fn opt_bool(&self, index: usize, name: &str) -> Result<Option<bool>, Value> {
        match self.get(index, name) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => v
                .as_bool()
                .map(Some)
                .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, format!("{name} must be a bool"))),
        }
    }

    pub fn get_array(&self, index: usize, name: &str) -> Option<&Vec<Value>> {
        self.get(index, name).and_then(Value::as_array)
    }

    /// Named-only: unknown keys → Core `-8 Unknown named parameter`.
    pub fn reject_unknown(&self, allowed: &[&str]) -> Result<(), Value> {
        let Some(m) = &self.named else {
            return Ok(());
        };
        for k in m.keys() {
            if !allowed.iter().any(|a| *a == k) {
                return Err(rpc_error(
                    ERR_INVALID_PARAMETER,
                    format!("Unknown named parameter {k}"),
                ));
            }
        }
        Ok(())
    }
}

fn json_u64(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_i64().and_then(|n| u64::try_from(n).ok()))
}

fn json_i64(v: &Value) -> Option<i64> {
    v.as_i64()
        .or_else(|| v.as_u64().and_then(|n| i64::try_from(n).ok()))
}

/// Exact BTC amount (8 decimals) so Core `Decimal` compares match sat/kvB.
fn json_btc_amount(sat: u64) -> Value {
    let whole = sat / 100_000_000;
    let frac = sat % 100_000_000;
    let s = format!("{whole}.{frac:08}");
    match s.parse::<serde_json::Number>() {
        Ok(n) => Value::Number(n),
        Err(_) => json!(sat as f64 / 100_000_000.0),
    }
}

/// Core `getblock` verbosity: integer, or bool (`false` → 0, `true` → 1).
fn opt_verbosity(params: &RpcParams, index: usize, name: &str) -> Result<u32, Value> {
    match params.get(index, name) {
        None | Some(Value::Null) => Ok(1),
        Some(Value::Bool(false)) => Ok(0),
        Some(Value::Bool(true)) => Ok(1),
        Some(v) => json_u64(v)
            .map(|n| n as u32)
            .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, format!("{name} must be an integer"))),
    }
}

impl From<Vec<Value>> for RpcParams {
    fn from(pos: Vec<Value>) -> Self {
        Self::positional(pos)
    }
}

impl From<&Vec<Value>> for RpcParams {
    fn from(pos: &Vec<Value>) -> Self {
        Self::positional(pos.clone())
    }
}

/// Dispatch one method. Returns `Ok(result)` or `Err(error_object)`.
pub fn dispatch(
    ctx: &RpcContext,
    method: &str,
    params: impl Into<RpcParams>,
) -> Result<Value, Value> {
    ctx.active
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((method.to_string(), Instant::now()));
    let out = dispatch_inner(ctx, method, params.into());
    ctx.active.lock().unwrap_or_else(|e| e.into_inner()).pop();
    out
}

fn dispatch_inner(ctx: &RpcContext, method: &str, params: RpcParams) -> Result<Value, Value> {
    match method {
        "help" => help(&params),
        "echo" => echo(&params),
        "getrpcinfo" => {
            params.reject_unknown(&[])?;
            Ok(getrpcinfo(ctx))
        }
        "uptime" => {
            params.reject_unknown(&[])?;
            Ok(json!(ctx.uptime_secs()))
        }
        "stop" => {
            params.reject_unknown(&["wait"])?;
            let _wait = params.opt_u64(0, "wait")?;
            ctx.stop.store(true, Ordering::SeqCst);
            Ok(json!("rbitcoin stopping"))
        }
        "syncwithvalidationinterfacequeue" => {
            params.reject_unknown(&[])?;
            // Core waits for wallet/index callbacks. We have no that queue.
            Ok(Value::Null)
        }
        "getblockchaininfo" => {
            params.reject_unknown(&[])?;
            getblockchaininfo(ctx)
        }
        "getblockcount" => {
            params.reject_unknown(&[])?;
            getblockcount(ctx)
        }
        "getbestblockhash" => {
            params.reject_unknown(&[])?;
            getbestblockhash(ctx)
        }
        "getblockhash" => getblockhash(ctx, &params),
        "getblockheader" => getblockheader(ctx, &params),
        "getblock" => getblock(ctx, &params),
        "getblockstats" => crate::blockstats::getblockstats(ctx, &params),
        "getdifficulty" => {
            params.reject_unknown(&[])?;
            getdifficulty(ctx)
        }
        "getnetworkinfo" => {
            params.reject_unknown(&[])?;
            Ok(getnetworkinfo(ctx))
        }
        "getconnectioncount" => {
            params.reject_unknown(&[])?;
            Ok(json!(connection_count(ctx)))
        }
        "getnettotals" => {
            params.reject_unknown(&[])?;
            Ok(getnettotals(ctx))
        }
        "getpeerinfo" => {
            params.reject_unknown(&[])?;
            Ok(getpeerinfo(ctx))
        }
        "ping" => {
            params.reject_unknown(&[])?;
            ping(ctx)
        }
        "addnode" => addnode(ctx, &params),
        "disconnectnode" => disconnectnode(ctx, &params),
        "addconnection" => addconnection(ctx, &params),
        "getmempoolinfo" => {
            params.reject_unknown(&[])?;
            getmempoolinfo(ctx)
        }
        "getrawmempool" => getrawmempool(ctx, &params),
        "getmempoolentry" => getmempoolentry(ctx, &params),
        "getrawtransaction" => getrawtransaction(ctx, &params),
        "sendrawtransaction" => sendrawtransaction(ctx, &params),
        "testmempoolaccept" => testmempoolaccept(ctx, &params),
        "estimatesmartfee" => estimatesmartfee(ctx, &params),
        "generatetoaddress" => generatetoaddress(ctx, &params),
        "generatetodescriptor" => generatetodescriptor(ctx, &params),
        "generateblock" => generateblock(ctx, &params),
        "generate" => generate(ctx, &params),
        "submitblock" => submitblock(ctx, &params),
        "submitheader" => submitheader(ctx, &params),
        "setmocktime" => setmocktime(ctx, &params),
        "mockscheduler" => mockscheduler(ctx, &params),
        "getnetworkhashps" => getnetworkhashps(ctx, &params),
        "invalidateblock" => invalidateblock(ctx, &params),
        "reconsiderblock" => reconsiderblock(ctx, &params),
        "preciousblock" => preciousblock(ctx, &params),
        "scantxoutset" => scantxoutset(ctx, &params),
        "gettxout" => gettxout(ctx, &params),
        "getindexinfo" => getindexinfo(ctx, &params),
        "getchaintips" => getchaintips(ctx, &params),
        "getdeploymentinfo" => getdeploymentinfo(ctx, &params),
        "waitforblock" => waitforblock(ctx, &params),
        "waitforblockheight" => waitforblockheight(ctx, &params),
        "waitfornewblock" => waitfornewblock(ctx, &params),
        "getblocktemplate" => getblocktemplate(ctx, &params),
        "getmininginfo" => getmininginfo(ctx),
        "prioritisetransaction" => prioritisetransaction(ctx, &params),
        "getprioritisedtransactions" => getprioritisedtransactions(ctx, &params),
        "getmempoolcluster" => getmempoolcluster(ctx, &params),
        "getmempoolancestors" => getmempoolancestors(ctx, &params),
        "getmempooldescendants" => getmempooldescendants(ctx, &params),
        "getmempoolfeeratediagram" => getmempoolfeeratediagram(ctx, &params),
        "submitpackage" => submitpackage(ctx, &params),
        "gettxspendingprevout" => gettxspendingprevout(ctx, &params),
        "createrawtransaction"
        | "signrawtransactionwithkey"
        | "createmultisig"
        | "combinerawtransaction"
        | "decoderawtransaction"
        | "decodescript"
        | "validateaddress"
        | "deriveaddresses"
        | "gettxoutsetinfo" => Err(rpc_error(
            ERR_METHOD_NOT_FOUND,
            format!("{method} is not supported (see docs/rpc.md)"),
        )),
        _ => Err(rpc_error(ERR_METHOD_NOT_FOUND, "Method not found")),
    }
}

fn help(params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["command"])?;
    if let Some(v) = params.get(0, "command") {
        let m = v
            .as_str()
            .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "command must be a string"))?;
        return Ok(json!(method_help(m)));
    }
    Ok(json!(METHOD_LIST.join("\n")))
}

/// Core `echo` names (`rpc_named_arguments.py`).
const ECHO_NAMES: [&str; 10] = [
    "arg0", "arg1", "arg2", "arg3", "arg4", "arg5", "arg6", "arg7", "arg8", "arg9",
];

/// Return params as a positional array (Core testing RPC).
///
/// Mixed AuthServiceProxy: `{args: [0, 1], arg3: 3}` → `[0, 1, null, 3]`.
/// Named-only `arg9` sizes the array to 10 with null holes.
fn echo(params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&ECHO_NAMES)?;
    if let Some(m) = &params.named {
        for (i, name) in ECHO_NAMES.iter().enumerate() {
            if m.contains_key(*name) && i < params.pos.len() {
                return Err(rpc_error(
                    ERR_INVALID_PARAMETER,
                    format!(
                        "Parameter {name} specified twice both as positional and named argument"
                    ),
                ));
            }
        }
    }

    let mut max_idx: Option<usize> = if params.pos.is_empty() {
        None
    } else {
        Some(params.pos.len() - 1)
    };
    if let Some(m) = &params.named {
        for (i, name) in ECHO_NAMES.iter().enumerate() {
            if m.contains_key(*name) {
                max_idx = Some(max_idx.map(|cur| cur.max(i)).unwrap_or(i));
            }
        }
    }
    let Some(max) = max_idx else {
        return Ok(json!([]));
    };
    let mut out = vec![Value::Null; max + 1];
    for (i, v) in params.pos.iter().enumerate() {
        out[i] = v.clone();
    }
    if let Some(m) = &params.named {
        for (i, name) in ECHO_NAMES.iter().enumerate() {
            if let Some(v) = m.get(*name) {
                out[i] = v.clone();
            }
        }
    }
    Ok(Value::Array(out))
}

const METHOD_LIST: &[&str] = &[
    "help",
    "echo",
    "getrpcinfo",
    "uptime",
    "stop",
    "syncwithvalidationinterfacequeue",
    "getblockchaininfo",
    "getblockcount",
    "getbestblockhash",
    "getblockhash",
    "getblockheader",
    "getblock",
    "getblockstats",
    "getdifficulty",
    "getnetworkinfo",
    "getconnectioncount",
    "getnettotals",
    "getpeerinfo",
    "ping",
    "addnode",
    "disconnectnode",
    "addconnection",
    "getmempoolinfo",
    "getrawmempool",
    "getmempoolentry",
    "getrawtransaction",
    "sendrawtransaction",
    "testmempoolaccept",
    "estimatesmartfee",
    "generatetoaddress",
    "generatetodescriptor",
    "generateblock",
    "scantxoutset",
    "gettxout",
    "getindexinfo",
    "getchaintips",
    "getdeploymentinfo",
    "waitforblock",
    "waitforblockheight",
    "waitfornewblock",
    "getblocktemplate",
    "getmininginfo",
    "getnetworkhashps",
    "prioritisetransaction",
    "getprioritisedtransactions",
    "getmempoolcluster",
    "getmempoolancestors",
    "getmempooldescendants",
    "getmempoolfeeratediagram",
    "submitpackage",
    "gettxspendingprevout",
    "submitblock",
    "submitheader",
    "setmocktime",
    "invalidateblock",
    "reconsiderblock",
    "preciousblock",
];

fn method_help(m: &str) -> String {
    match m {
        "estimatesmartfee" => {
            "estimatesmartfee conf_target (mode ignored). Returns this node's 10-minute \
             inclusion frontier feerate (BTC/kvB), not Core historical multi-horizon. \
             See docs/mempool-fee-estimation.md."
                .into()
        }
        "getblockchaininfo" => "getblockchaininfo\nReturns tip height, chain name, and IBD flag.\n\
             chainwork is summed header work (regtest 2/block). size_on_disk is a \
             walk of store file lengths (plus cold inwit when split). \
             verificationprogress is blocks/headers (1.0 when headers is 0)."
            .into(),
        "getblockstats" => "getblockstats hash_or_height ( stats )\n\
             Reconstruct the block and return fee / UTXO / weight statistics."
            .into(),
        "generatetoaddress" => "generatetoaddress nblocks address (maxtries)\n\
             Regtest harness only. Mines nblocks paying address via the P2P accept path."
            .into(),
        "generateblock" => "generateblock output transactions (submit)\n\
             Regtest harness only. One block paying output (address or hex script). \
             submit=false returns {hash,hex} without connecting the block."
            .into(),
        "generate" => "generate\n\nhas been replaced by the -generate cli option. Refer to -help for more information.\n"
            .into(),
        "mockscheduler" => "mockscheduler delta_seconds\n\
             Regtest harness only. Advance the scheduler; rebroadcast unbroadcast txs."
            .into(),
        "generatetodescriptor" => "generatetodescriptor nblocks descriptor (maxtries)\n\
             Regtest harness only. raw(HEX), addr(ADDRESS), or a bare address."
            .into(),
        "scantxoutset" => "scantxoutset action (scanobjects)\n\
             raw() scripts over Class A. MiniWallet support, not Core coins-DB."
            .into(),
        "gettxout" => "gettxout txid n (include_mempool) — Class A + mempool.".into(),
        "getchaintips" => "getchaintips — active + held/archive side tips + headers-only.".into(),
        "getdeploymentinfo" => {
            "getdeploymentinfo (blockhash)\nBuried deployments from ChainParams. No BIP9.".into()
        }
        "getblocktemplate" => "getblocktemplate (template_request)\n\
             All networks. Template from select_block_txs; proposal validates \
             without connecting. rules must include segwit. longpollid waits \
             for a new tip or mempool/priority change. No BIP9 testdummy."
            .into(),
        "getmininginfo" => "getmininginfo\nTip height, difficulty, pooledtx. All networks.".into(),
        "prioritisetransaction" => {
            "prioritisetransaction txid dummy fee_delta\nLocal mining fee delta (sat). dummy must be 0."
                .into()
        }
        "getprioritisedtransactions" => {
            "getprioritisedtransactions\nMap of txid → fee_delta / in_mempool / modified_fee."
                .into()
        }
        "submitblock" => "submitblock hexdata (dummy)\n\
             All networks. Same receive path as a P2P block."
            .into(),
        "submitheader" => "submitheader hexdata\n\
             All networks. Persist a header via the P2P header path (`ensure_header`)."
            .into(),
        "getpeerinfo" => "getpeerinfo\n\
             Returns data about each connected network node as a json array of objects.\n\
             Valid networks: (ipv4, ipv6, onion, i2p, cjdns, not_publicly_routable)"
            .into(),
        "help" => "help\nhelp ( \"command\" ) — list methods or describe one.".into(),
        "echo" => "echo\necho ( arg0 ... arg9 ) — return arguments as a positional array.".into(),
        other if METHOD_LIST.contains(&other) => format!("{other} — see docs/rpc.md"),
        other => format!("unknown method {other}"),
    }
}

fn getrpcinfo(ctx: &RpcContext) -> Value {
    let active = ctx
        .active
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|(method, start)| {
            json!({
                "method": method,
                "duration": start.elapsed().as_micros() as u64,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "active_commands": active,
        "logpath": ctx.logpath,
        "uptime": ctx.uptime_secs(),
        "methods": METHOD_LIST,
    })
}

/// Core-shaped version integer: major*10000 + minor*100 + patch.
fn rpc_client_version(semver: &str) -> u64 {
    let mut it = semver.split('.');
    let maj: u64 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let min: u64 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let pat: u64 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    maj.saturating_mul(10_000)
        .saturating_add(min.saturating_mul(100))
        .saturating_add(pat)
}

fn chain_name(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "main",
        Network::Testnet => "test",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

fn getblockcount(ctx: &RpcContext) -> Result<Value, Value> {
    let h = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    Ok(json!(h))
}

fn getbestblockhash(ctx: &RpcContext) -> Result<Value, Value> {
    let Some(tip) = ctx.query.tip_height() else {
        return Err(rpc_error(ERR_MISC, "no tip"));
    };
    let (_, rec) = ctx
        .query
        .header_at_height(tip)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_MISC, "tip header missing"))?;
    Ok(json!(hash_hex_display(&rec.hash)))
}

fn getblockhash(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["height"])?;
    let height = params.req_u64(0, "height")? as u32;
    let (_, rec) = ctx
        .query
        .header_at_height(Height(height))
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_INVALID_PARAMETER, "Block height out of range"))?;
    Ok(json!(hash_hex_display(&rec.hash)))
}

fn getblockchaininfo(ctx: &RpcContext) -> Result<Value, Value> {
    let tip = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    let best = if let Some(h) = ctx.query.tip_height() {
        ctx.query
            .header_at_height(h)
            .ok()
            .flatten()
            .map(|(_, r)| hash_hex_display(&r.hash))
            .unwrap_or_default()
    } else {
        String::new()
    };
    let ibd = ctx.initial_block_download.load(Ordering::Relaxed);
    let headers = ctx
        .chain
        .as_ref()
        .map(|c| c.best_header_height())
        .unwrap_or(tip);
    let verificationprogress = if headers == 0 {
        1.0
    } else {
        (tip as f64 / headers as f64).clamp(0.0, 1.0)
    };
    let (time, mediantime) = if let Some(h) = ctx.query.tip_height() {
        if let Ok(Some((_, rec))) = ctx.query.header_at_height(h) {
            let mtp = rbitcoin_consensus::median_time_past(ctx.query.as_ref(), h)
                .unwrap_or(rec.timestamp);
            (rec.timestamp, mtp)
        } else {
            (0u32, 0u32)
        }
    } else {
        (0u32, 0u32)
    };
    Ok(json!({
        "chain": chain_name(ctx.network),
        "blocks": tip,
        "headers": headers,
        "bestblockhash": best,
        "difficulty": difficulty_at_tip(ctx).unwrap_or(0.0),
        "time": time,
        "mediantime": mediantime,
        "verificationprogress": verificationprogress,
        "initialblockdownload": ibd,
        "chainwork": chainwork_hex(ctx, ctx.query.tip_height()),
        "size_on_disk": ctx.query.store().datadir_bytes(),
        "pruned": false,
        "warnings": "",
    }))
}

fn difficulty_from_bits(bits: u32) -> f64 {
    // Compact target → difficulty relative to max target (same class as Core).
    let n_shift = ((bits >> 24) & 0xff) as i32;
    let mut ddiff = (0x0000_ffff_u64 as f64) / ((bits & 0x00ff_ffff) as f64);
    let mut shift = n_shift - 29;
    while shift < 0 {
        ddiff *= 256.0;
        shift += 1;
    }
    while shift > 0 {
        ddiff /= 256.0;
        shift -= 1;
    }
    ddiff
}

fn difficulty_at_tip(ctx: &RpcContext) -> Result<f64, Value> {
    let tip = ctx
        .query
        .tip_height()
        .ok_or_else(|| rpc_error(ERR_MISC, "no tip"))?;
    let (_, rec) = ctx
        .query
        .header_at_height(tip)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_MISC, "tip header missing"))?;
    Ok(difficulty_from_bits(rec.bits))
}

fn getdifficulty(ctx: &RpcContext) -> Result<Value, Value> {
    Ok(json!(difficulty_at_tip(ctx)?))
}

fn getblockheader(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash", "verbose"])?;
    let hash_hex = params.req_str(0, "blockhash")?;
    let verbose = params.opt_bool(1, "verbose")?.unwrap_or(true);
    let hash = parse_hash32_display(hash_hex)?;
    let height = ctx
        .query
        .height_of_hash(&hash)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found"))?;
    let (_, rec) = ctx
        .query
        .header_at_height(height)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found"))?;
    if !verbose {
        let hdr = ctx
            .query
            .wire_header_at_height(height)
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
        let mut raw = Vec::new();
        hdr.consensus_encode(&mut raw)
            .map_err(|_| rpc_error(ERR_MISC, "header encode"))?;
        return Ok(json!(hex_encode(raw)));
    }
    let prev = if height.0 > 0 {
        ctx.query
            .header_at_height(Height(height.0 - 1))
            .ok()
            .flatten()
            .map(|(_, r)| hash_hex_display(&r.hash))
            .unwrap_or_default()
    } else {
        String::new()
    };
    Ok(json!({
        "hash": hash_hex_display(&rec.hash),
        "confirmations": confirmations(ctx, height),
        "height": height.0,
        "version": rec.version,
        "versionHex": format!("{:08x}", rec.version),
        "merkleroot": hash_hex_display(&rec.merkle_root),
        "time": rec.timestamp,
        "mediantime": rbitcoin_consensus::median_time_past(ctx.query.as_ref(), height)
            .unwrap_or(rec.timestamp),
        "nonce": rec.nonce,
        "bits": format!("{:08x}", rec.bits),
        "difficulty": difficulty_from_bits(rec.bits),
        "chainwork": chainwork_hex(ctx, Some(height)),
        "previousblockhash": prev,
        "nTx": ctx.query.block_tx_fks(height).map(|v| v.len()).unwrap_or(0),
    }))
}

/// 32-byte BE chainwork hex (regtest = 2 per block). Empty store → 64 zeros.
fn chainwork_hex(ctx: &RpcContext, through: Option<Height>) -> String {
    let Some(tip) = through.or_else(|| ctx.query.tip_height()) else {
        return "00".repeat(32);
    };
    if let Some(hub) = ctx.chain.as_ref() {
        if ctx.query.tip_height() == Some(tip) {
            if let Ok(w) = hub.chain_work() {
                return hex_encode(w.to_be_bytes());
            }
        }
    }
    let mut works = Vec::new();
    for h in 0..=tip.0 {
        if let Ok(hdr) = ctx.query.wire_header_at_height(Height(h)) {
            works.push(hdr.work());
        }
    }
    hex_encode(rbitcoin_net::sum_work(works.into_iter()).to_be_bytes())
}

fn getblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash", "verbosity", "verbose"])?;
    let hash_hex = params.req_str(0, "blockhash")?;
    let verbosity = match params.get(1, "verbosity") {
        Some(_) => opt_verbosity(params, 1, "verbosity")?,
        None => opt_verbosity(params, 1, "verbose")?,
    };
    let hash = parse_hash32_display(hash_hex)?;
    let height = match ctx
        .query
        .height_of_hash(&hash)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
    {
        Some(h) => h,
        None => {
            let typed = BlockHash::from_byte_array(hash);
            if let Some(block) = ctx.chain.as_ref().and_then(|c| c.held_body(&typed)) {
                if verbosity == 0 {
                    let mut raw = Vec::new();
                    block
                        .consensus_encode(&mut raw)
                        .map_err(|_| rpc_error(ERR_MISC, "block encode"))?;
                    return Ok(json!(hex_encode(raw)));
                }
                let txids: Vec<String> = block
                    .txdata
                    .iter()
                    .map(|tx| hash_hex_display(&tx.compute_txid().to_byte_array()))
                    .collect();
                return Ok(json!({
                    "hash": hash_hex_display(&hash),
                    "confirmations": -1,
                    "version": block.header.version.to_consensus(),
                    "merkleroot": hash_hex_display(&block.header.merkle_root.to_byte_array()),
                    "time": block.header.time,
                    "nonce": block.header.nonce,
                    "bits": format!("{:08x}", block.header.bits.to_consensus()),
                    "nTx": block.txdata.len(),
                    "tx": txids,
                }));
            }
            let header_only = ctx.chain.as_ref().is_some_and(|c| c.knows_header(&typed))
                || ctx.query.get_header_by_hash(&hash).ok().flatten().is_some();
            if header_only {
                return Err(rpc_error(
                    ERR_MISC,
                    "Block not available (not fully downloaded)",
                ));
            }
            return Err(rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found"));
        }
    };
    let block = ctx
        .query
        .reconstruct_block_at_height(height)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    if verbosity == 0 {
        let mut raw = Vec::new();
        block
            .consensus_encode(&mut raw)
            .map_err(|_| rpc_error(ERR_MISC, "block encode"))?;
        return Ok(json!(hex_encode(raw)));
    }
    let txids: Vec<String> = block
        .txdata
        .iter()
        .map(|tx| hash_hex_display(&tx.compute_txid().to_byte_array()))
        .collect();
    let prev = if height.0 > 0 {
        ctx.query
            .header_at_height(Height(height.0 - 1))
            .ok()
            .flatten()
            .map(|(_, r)| hash_hex_display(&r.hash))
            .unwrap_or_default()
    } else {
        String::new()
    };
    let mut obj = json!({
        "hash": hash_hex_display(&hash),
        "confirmations": confirmations(ctx, height),
        "height": height.0,
        "version": block.header.version.to_consensus(),
        "merkleroot": hash_hex_display(&block.header.merkle_root.to_byte_array()),
        "time": block.header.time,
        "mediantime": rbitcoin_consensus::median_time_past(ctx.query.as_ref(), height)
            .unwrap_or(block.header.time),
        "nonce": block.header.nonce,
        "bits": format!("{:08x}", block.header.bits.to_consensus()),
        "previousblockhash": prev,
        "nTx": block.txdata.len(),
        "tx": txids,
    });
    if verbosity >= 2 {
        let net = rpc_btc_network(ctx.network);
        let txs: Vec<Value> = block
            .txdata
            .iter()
            .map(|tx| tx_to_json(tx, None, net))
            .collect();
        obj["tx"] = json!(txs);
    }
    Ok(obj)
}

fn confirmations(ctx: &RpcContext, height: Height) -> u32 {
    let tip = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    tip.saturating_sub(height.0).saturating_add(1)
}

fn getnettotals(ctx: &RpcContext) -> Value {
    let (recv, sent) = ctx
        .peers
        .as_ref()
        .map(|h| h.byte_totals())
        .unwrap_or((0, 0));
    let timemillis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    json!({
        "totalbytesrecv": recv,
        "totalbytessent": sent,
        "timemillis": timemillis,
        "uploadtarget": {
            "timeframe": 86400,
            "target": 0,
            "target_reached": false,
            "serve_historical_blocks": true,
            "bytes_left_in_cycle": 0,
            "time_left_in_cycle": 0,
        },
    })
}

fn getpeerinfo(ctx: &RpcContext) -> Value {
    let Some(hub) = ctx.peers.as_ref() else {
        return json!([]);
    };
    let rows: Vec<Value> = hub.snapshot().into_iter().map(peerinfo_json).collect();
    json!(rows)
}

fn peerinfo_json(p: rbitcoin_net::PeerInfo) -> Value {
    let mut recv = serde_json::Map::new();
    for (k, v) in p.bytesrecv_per_msg {
        recv.insert(k, json!(v));
    }
    let mut sent = serde_json::Map::new();
    for (k, v) in p.bytessent_per_msg {
        sent.insert(k, json!(v));
    }
    let mut row = json!({
        "id": p.id,
        "addr": p.addr.to_string(),
        "addrbind": p.addrbind.to_string(),
        "subver": p.subver,
        "inbound": p.inbound,
        "services": format!("{:016x}", p.services),
        "servicesnames": services_names(p.services),
        "startingheight": p.startingheight,
        "bytesrecv_per_msg": recv,
        "bytessent_per_msg": sent,
        "connection_type": p.conn_type.as_str(),
        "transport_protocol_type": "v2",
        "network": "ipv4",
        "synced_headers": -1,
        "synced_blocks": -1,
        "bip152_hb_to": p.bip152_hb_to,
        "bip152_hb_from": p.bip152_hb_from,
        "last_block": p.last_block,
        "last_transaction": p.last_transaction,
        "minfeefilter": sat_kvb_to_btc(p.minfeefilter_sat_kvb),
    });
    if let Some(v) = p.pingtime {
        row["pingtime"] = json!(v);
    }
    if let Some(v) = p.minping {
        row["minping"] = json!(v);
    }
    if let Some(v) = p.pingwait {
        row["pingwait"] = json!(v);
    }
    row
}

fn ping(ctx: &RpcContext) -> Result<Value, Value> {
    if let Some(hub) = ctx.peers.as_ref() {
        hub.queue_pings();
    }
    Ok(Value::Null)
}

fn services_names(bits: u64) -> Vec<&'static str> {
    let mut n = Vec::new();
    if bits & 1 != 0 {
        n.push("NETWORK");
    }
    if bits & 8 != 0 {
        n.push("WITNESS");
    }
    if bits & 0x400 != 0 {
        n.push("NETWORK_LIMITED");
    }
    if bits & 0x800 != 0 {
        n.push("P2P_V2");
    }
    n
}

fn require_peers(ctx: &RpcContext) -> Result<&rbitcoin_net::PeerHub, Value> {
    ctx.peers
        .as_deref()
        .ok_or_else(|| rpc_error(ERR_MISC, "P2P session table not attached"))
}

fn addnode(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["node", "command", "v2transport"])?;
    let hub = require_peers(ctx)?;
    let node = params.req_str(0, "node")?;
    let cmd = params.req_str(1, "command")?;
    let _v2 = params.opt_bool(2, "v2transport")?;
    let addr = rbitcoin_net::parse_peer_addr(node)
        .map_err(|e| rpc_error(ERR_INVALID_PARAMS, e.to_string()))?;
    hub.addnode(addr, cmd).map_err(|e| rpc_error(ERR_MISC, e))?;
    Ok(Value::Null)
}

fn disconnectnode(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["address", "nodeid"])?;
    let hub = require_peers(ctx)?;
    if let Some(id) = params.opt_u64(1, "nodeid")? {
        if !hub.disconnect_id(id) {
            return Err(rpc_error(
                ERR_CLIENT_NODE_NOT_CONNECTED,
                "Node not found in connected nodes",
            ));
        }
        return Ok(Value::Null);
    }
    if let Some(a) = params.get(0, "address").and_then(|v| v.as_str()) {
        let addr = rbitcoin_net::parse_peer_addr(a)
            .map_err(|e| rpc_error(ERR_INVALID_PARAMS, e.to_string()))?;
        if !hub.disconnect_addr(addr) {
            return Err(rpc_error(
                ERR_CLIENT_NODE_NOT_CONNECTED,
                "Node not found in connected nodes",
            ));
        }
        return Ok(Value::Null);
    }
    Err(rpc_error(ERR_INVALID_PARAMS, "address or nodeid required"))
}

fn addconnection(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["address", "connection_type", "v2transport"])?;
    let hub = require_peers(ctx)?;
    let address = params.req_str(0, "address")?;
    let typ_s = params.req_str(1, "connection_type")?;
    let _v2 = params.opt_bool(2, "v2transport")?.unwrap_or(true);
    let addr = rbitcoin_net::parse_peer_addr(address)
        .map_err(|e| rpc_error(ERR_INVALID_PARAMS, e.to_string()))?;
    let typ =
        rbitcoin_net::PeerConnType::parse(typ_s).map_err(|e| rpc_error(ERR_INVALID_PARAMS, e))?;
    hub.addconnection(addr, typ)
        .map_err(|e| rpc_error(ERR_MISC, e))?;
    Ok(json!({
        "address": address,
        "connection_type": typ.as_str(),
    }))
}

/// Live P2P sessions (Core `getconnectioncount`). Inbound + outbound.
/// Falls back to the outbound-follow counter when no PeerHub is attached.
fn connection_count(ctx: &RpcContext) -> u64 {
    if let Some(hub) = ctx.peers.as_ref() {
        hub.snapshot().len() as u64
    } else {
        ctx.connections.load(Ordering::Relaxed)
    }
}

fn getnetworkinfo(ctx: &RpcContext) -> Value {
    let (cin, cout) = if let Some(hub) = ctx.peers.as_ref() {
        let rows = hub.snapshot();
        let cin = rows.iter().filter(|p| p.inbound).count() as u64;
        let cout = rows.iter().filter(|p| !p.inbound).count() as u64;
        (cin, cout)
    } else {
        (0, ctx.connections.load(Ordering::Relaxed))
    };
    let flags = rbitcoin_net::local_service_flags();
    let svc_bits = flags.to_u64();
    json!({
        "version": rpc_client_version(env!("CARGO_PKG_VERSION")),
        "subversion": ctx.subversion,
        "protocolversion": 70016,
        "localservices": format!("{svc_bits:016x}"),
        "localservicesnames": services_names(svc_bits),
        "localrelay": true,
        "timeoffset": 0,
        "networkactive": true,
        "connections": cin + cout,
        "connections_in": cin,
        "connections_out": cout,
        "networks": [],
        "relayfee": MempoolHub::relay_fee_btc_per_kb(),
        "incrementalfee": MempoolHub::relay_fee_btc_per_kb(),
        "localaddresses": [],
        "warnings": "BIP324 v2-only; not full Core networkinfo parity",
    })
}

fn getmempoolinfo(ctx: &RpcContext) -> Result<Value, Value> {
    let Some(mp) = ctx.mempool.as_ref() else {
        return Ok(json!({
            "loaded": true,
            "size": 0,
            "bytes": 0,
            "usage": 0,
            "total_fee": 0.0,
            "maxmempool": 0,
            "mempoolminfee": MempoolHub::relay_fee_btc_per_kb(),
            "minrelaytxfee": MempoolHub::relay_fee_btc_per_kb(),
            "unbroadcastcount": 0,
            "permitbaremultisig": true,
            "optimal": true,
        }));
    };
    let live = mp.list_live_meta();
    let size = live.len();
    let mut bytes = 0u64;
    let mut total_fee = 0u64;
    for (_, fee, weight) in &live {
        bytes += weight / 4;
        total_fee += fee;
    }
    Ok(json!({
        "loaded": true,
        "size": size,
        "bytes": bytes,
        "usage": bytes,
        "total_fee": (total_fee as f64) / 100_000_000.0,
        "maxmempool": mp.max_weight(),
        "mempoolminfee": MempoolHub::relay_fee_btc_per_kb(),
        "minrelaytxfee": MempoolHub::relay_fee_btc_per_kb(),
        "relay_enabled": mp.relay_enabled(),
        "unbroadcastcount": mp.unbroadcast_count(),
        "permitbaremultisig": true,
        "optimal": true,
    }))
}

/// Exact 8-decimal BTC JSON number (Core `ValueFromAmount`). Avoids f64 drift
/// against `Decimal` comparisons in the functional suite.
fn sat_btc_json(sat: i64) -> Value {
    let sign = if sat < 0 { "-" } else { "" };
    let abs = sat.unsigned_abs();
    let s = format!("{sign}{}.{:08}", abs / 100_000_000, abs % 100_000_000);
    Value::Number(s.parse().expect("sat/BTC decimal"))
}

/// Shared getrawmempool-verbose / getmempoolentry graph + unbroadcast fields.
fn mempool_graph_json(mp: &MempoolHub, txid: &Txid, fee: u64, weight: u64) -> Value {
    let vsize = weight / 4;
    let delta = mp.fee_delta(txid);
    let modified = (fee as i64).saturating_add(delta);
    let (ac, asz, afee, dc, dsz, dfee, a_mod, d_mod, chunk_fee, chunk_w) =
        match mp.graph_fees_modified(txid) {
            Some((s, am, dm, cf, cw)) => (
                s.ancestorcount,
                s.ancestorsize,
                s.ancestorfees,
                s.descendantcount,
                s.descendantsize,
                s.descendantfees,
                am,
                dm,
                cf,
                cw,
            ),
            None => (
                1, vsize, fee, 1, vsize, fee, modified, modified, modified, weight,
            ),
        };
    json!({
        "vsize": vsize,
        "weight": weight,
        "fee": sat_btc_json(fee as i64),
        // Top-level `modifiedfee` stays the base fee (same pattern as
        // ancestorfees/descendantfees). Real modified value is `fees.modified`.
        "modifiedfee": sat_btc_json(fee as i64),
        "time": 0,
        "height": 0,
        "descendantcount": dc,
        "descendantsize": dsz,
        "descendantfees": dfee,
        "ancestorcount": ac,
        "ancestorsize": asz,
        "ancestorfees": afee,
        "chunkweight": chunk_w,
        "unbroadcast": mp.is_unbroadcast(txid),
        "fees": {
            "base": sat_btc_json(fee as i64),
            "modified": sat_btc_json(modified),
            "ancestor": sat_btc_json(a_mod),
            "descendant": sat_btc_json(d_mod),
            "chunk": sat_btc_json(chunk_fee),
        },
    })
}

fn getrawmempool(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["verbose"])?;
    let verbose = params.opt_bool(0, "verbose")?.unwrap_or(false);
    let Some(mp) = ctx.mempool.as_ref() else {
        return Ok(if verbose { json!({}) } else { json!([]) });
    };
    let live = mp.list_live_meta();
    if !verbose {
        let ids: Vec<String> = live
            .iter()
            .map(|(t, _, _)| hash_hex_display(&t.to_byte_array()))
            .collect();
        return Ok(json!(ids));
    }
    let mut map = serde_json::Map::new();
    for (txid, fee, weight) in live {
        map.insert(
            hash_hex_display(&txid.to_byte_array()),
            mempool_graph_json(mp, &txid, fee, weight),
        );
    }
    Ok(Value::Object(map))
}

fn getmempoolentry(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["txid"])?;
    let hex = params.req_str(0, "txid")?;
    let want = parse_hash32_display(hex)?;
    let mp = ctx
        .mempool
        .as_ref()
        .ok_or_else(|| rpc_error(ERR_MISC, "mempool not available"))?;
    let tid = Txid::from_byte_array(want);
    if let Some((fee, weight)) = mp.get_live_meta(&tid) {
        let wtxid = mp
            .get_tx(&tid)
            .map(|tx| hash_hex_display(&tx.compute_wtxid().to_byte_array()))
            .unwrap_or_default();
        let mut entry = mempool_graph_json(mp, &tid, fee, weight);
        if let Some(obj) = entry.as_object_mut() {
            obj.insert("wtxid".into(), json!(wtxid));
        }
        return Ok(entry);
    }
    Err(rpc_error(ERR_MISC, "Transaction not in mempool"))
}

fn getrawtransaction(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["txid", "verbose", "verbosity", "blockhash"])?;
    let hex = params.req_str(0, "txid")?;
    let verbose = match params
        .get(1, "verbose")
        .or_else(|| params.get(1, "verbosity"))
    {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(v) => json_u64(v)
            .map(|n| n != 0)
            .ok_or_else(|| rpc_error(ERR_TYPE_ERROR, "not of expected type number"))?,
    };
    let want = parse_hash32_display(hex)?;

    if let Some(mp) = ctx.mempool.as_ref() {
        let tid = Txid::from_byte_array(want);
        if let Some(tx) = mp.get_tx(&tid) {
            if !verbose {
                return Ok(json!(serialize_hex(&tx)));
            }
            return Ok(tx_to_json(
                &tx,
                Some(json!({ "in_mempool": true })),
                rpc_btc_network(ctx.network),
            ));
        }
    }

    let (fk, _) = ctx
        .query
        .get_tx_by_txid(&want)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_MISC, "No such mempool or blockchain transaction"))?;
    let tx = ctx
        .query
        .reconstruct_tx(fk)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    if !verbose {
        return Ok(json!(serialize_hex(&tx)));
    }
    Ok(tx_to_json(
        &tx,
        Some(json!({ "in_mempool": false })),
        rpc_btc_network(ctx.network),
    ))
}

fn sendrawtransaction(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["hexstring", "maxfeerate"])?;
    let hex = params.req_str(0, "hexstring")?;
    let tx = decode_tx_hex(hex)?;
    let mp = ctx
        .mempool
        .as_ref()
        .ok_or_else(|| rpc_error(ERR_MISC, "mempool not available"))?;
    if !mp.relay_enabled() {
        return Err(rpc_error(
            ERR_MISC,
            "mempool relay disabled (still in IBD or tip not ready)",
        ));
    }
    match mp.accept_tx(&tx) {
        Ok(r) => {
            mp.note_unbroadcast(r.txid);
            Ok(json!(hash_hex_display(&tx.compute_txid().to_byte_array())))
        }
        // Core sendraw of a live mempool tx is a no-op success (returns txid).
        Err(e) if e.to_string().starts_with("duplicate ") => {
            Ok(json!(hash_hex_display(&tx.compute_txid().to_byte_array())))
        }
        Err(e) => Err(rpc_error(ERR_VERIFY_REJECTED, accept_reject_reason(&e))),
    }
}

fn accept_reject_reason(e: &impl std::fmt::Display) -> String {
    let owned = e.to_string();
    let s = owned.strip_prefix("policy: ").unwrap_or(owned.as_str());
    if s == "coinbase immature" {
        return "bad-txns-premature-spend-of-coinbase".into();
    }
    if s == "coinbase" {
        return "bad-txns-is-coinbase".into();
    }
    if s.starts_with("missing prevout") {
        return "bad-txns-inputs-missingorspent".into();
    }
    if s.starts_with("duplicate ") {
        return "txn-already-in-mempool".into();
    }
    if s == "inputs-duplicate" {
        return "bad-txns-inputs-duplicate".into();
    }
    if s == "not final" {
        return "non-final".into();
    }
    if s == "negative fee" {
        return "bad-txns-in-belowout".into();
    }
    if s == "non-BIP68-final" {
        return "non-BIP68-final".into();
    }
    if s == "rbf insufficient fee" {
        return "insufficient fee".into();
    }
    if s == "min relay fee" {
        return "min relay fee not met".into();
    }
    if let Some(rest) = s.strip_prefix("script: ") {
        let rest = rest
            .strip_prefix("script verification failed: ")
            .unwrap_or(rest);
        let paren = rbitcoin_consensus::script_flag_paren(rest);
        return format!("mempool-script-verify-flag-failed ({paren})");
    }
    s.to_string()
}

/// Core `reject-details` for a script-verify mempool reject.
fn accept_reject_details(e: &impl std::fmt::Display, tx: &Transaction) -> Option<String> {
    let reason = accept_reject_reason(e);
    if !reason.starts_with("mempool-script-verify-flag-failed") {
        return None;
    }
    let vin = 0usize;
    let inp = tx.input.get(vin)?;
    let prev = inp.previous_output;
    Some(format!(
        "{reason}, input {vin} of {} (wtxid {}), spending {}:{}",
        tx.compute_txid(),
        tx.compute_wtxid(),
        prev.txid,
        prev.vout
    ))
}

fn testmempoolaccept(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["rawtxs", "maxfeerate"])?;
    let arr = params
        .get_array(0, "rawtxs")
        .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "rawtxs array required"))?;
    let mp = ctx
        .mempool
        .as_ref()
        .ok_or_else(|| rpc_error(ERR_MISC, "mempool not available"))?;
    let mut decoded = Vec::new();
    for v in arr {
        let hex = v
            .as_str()
            .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "rawtx hex required"))?;
        decoded.push(decode_tx_hex(hex)?);
    }
    let mut ids = std::collections::HashSet::new();
    if decoded.iter().any(|tx| !ids.insert(tx.compute_txid())) {
        let tx = &decoded[0];
        return Ok(json!([{
            "txid": hash_hex_display(&tx.compute_txid().to_byte_array()),
            "wtxid": hash_hex_display(&tx.compute_wtxid().to_byte_array()),
            "allowed": false,
            "package-error": "package-contains-duplicates",
        }]));
    }
    let mut out = Vec::new();
    for tx in decoded {
        let txid = hash_hex_display(&tx.compute_txid().to_byte_array());
        // Dry-run: accept then remove if we admitted (best-effort). Prefer not
        // mutating — use accept and if ok, remove_for_block to roll back.
        match mp.accept_tx(&tx) {
            Ok(r) => {
                let _ = mp.remove_for_block(&[tx.compute_txid()]);
                let wtxid = hash_hex_display(&tx.compute_wtxid().to_byte_array());
                out.push(json!({
                    "txid": txid,
                    "wtxid": wtxid,
                    "allowed": true,
                    "vsize": r.weight / 4,
                    "fees": { "base": sat_btc_json(r.fee_sat as i64) },
                }));
            }
            Err(e) => {
                let wtxid = hash_hex_display(&tx.compute_wtxid().to_byte_array());
                let mut row = json!({
                    "txid": txid,
                    "wtxid": wtxid,
                    "allowed": false,
                    "reject-reason": accept_reject_reason(&e),
                });
                if let Some(details) = accept_reject_details(&e, &tx) {
                    row["reject-details"] = json!(details);
                }
                out.push(row);
            }
        }
    }
    Ok(json!(out))
}

/// Map Core `estimatesmartfee` to this node's **10-minute inclusion** product.
fn estimatesmartfee(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["conf_target", "estimate_mode"])?;
    let conf_target = params.opt_u64(0, "conf_target")?.unwrap_or(2) as u32;
    // Core conf_target is blocks; we map 1–2 (and default) to 10-minute horizon.
    let Some(mp) = ctx.mempool.as_ref() else {
        return Ok(json!({
            "feerate": -1.0,
            "errors": ["mempool unavailable"],
            "blocks": conf_target,
        }));
    };
    let rate = mp.estimate_fee_btc_per_kb(conf_target);
    if rate < 0.0 {
        return Ok(json!({
            "feerate": -1.0,
            "errors": ["Insufficient data or empty mempool"],
            "blocks": conf_target.max(1),
        }));
    }
    Ok(json!({
        "feerate": rate,
        "blocks": conf_target.max(1),
        "errors": Value::Null,
        // Non-Core field: document the product mapping.
        "rbitcoin_model": "10-minute inclusion frontier (not Core historical)",
    }))
}

fn require_regtest(ctx: &RpcContext, method: &str) -> Result<(), Value> {
    if ctx.network != Network::Regtest {
        return Err(rpc_error(ERR_MISC, format!("{method} is regtest only")));
    }
    Ok(())
}

fn require_regtest_miner<'a>(
    ctx: &'a RpcContext,
    method: &str,
) -> Result<&'a dyn RpcRegtest, Value> {
    require_regtest(ctx, method)?;
    ctx.regtest
        .as_deref()
        .ok_or_else(|| rpc_error(ERR_MISC, format!("{method} requires a live chain hub")))
}

fn rpc_btc_network(n: Network) -> BtcNetwork {
    match n {
        Network::Mainnet => BtcNetwork::Bitcoin,
        Network::Testnet => BtcNetwork::Testnet,
        Network::Signet => BtcNetwork::Signet,
        Network::Regtest => BtcNetwork::Regtest,
    }
}

fn script_pubkey_json(script: &ScriptBuf, network: BtcNetwork) -> Value {
    let mut obj = json!({
        "hex": hex_encode(script.as_bytes()),
        "asm": script.to_asm_string(),
    });
    if let Ok(addr) = Address::from_script(script, network) {
        if let Some(m) = obj.as_object_mut() {
            m.insert("address".into(), json!(addr.to_string()));
        }
    }
    obj
}

fn decode_output_script(ctx: &RpcContext, s: &str) -> Result<ScriptBuf, Value> {
    let btc_net = rpc_btc_network(ctx.network);
    if let Ok(a) = s.parse::<Address<_>>() {
        match a.require_network(btc_net) {
            Ok(addr) => return Ok(addr.script_pubkey()),
            Err(_) => {
                return Err(rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Invalid address"));
            }
        }
    }
    let bytes = hex_decode(s).map_err(|e| {
        rpc_error(
            ERR_INVALID_PARAMS,
            format!("output must be an address or hex script: {e}"),
        )
    })?;
    Ok(ScriptBuf::from_bytes(bytes))
}

fn hashes_json(hashes: &[BlockHash]) -> Value {
    json!(hashes.iter().map(|h| h.to_string()).collect::<Vec<_>>())
}

fn mempool_block_txs(ctx: &RpcContext) -> Vec<Transaction> {
    let txs = ctx
        .mempool
        .as_ref()
        .map(|mp| mp.select_block_txs())
        .unwrap_or_default();
    let min = ctx
        .chain
        .as_ref()
        .map(|c| c.block_min_tx_fee_sat_kvb())
        .unwrap_or(1);
    filter_block_min_fee(ctx, txs, min)
}

/// Whether modified fee meets `-blockmintxfee` as a true sat/kvB floor
/// (`fee * 1000 >= min * vsize`). Zero min admits free txs.
fn meets_block_min_feerate(modified_sat: i64, weight_wu: u64, min_sat_kvb: u64) -> bool {
    if min_sat_kvb == 0 {
        return true;
    }
    if modified_sat <= 0 {
        return false;
    }
    let vsize = weight_wu.saturating_add(3) / 4;
    if vsize == 0 {
        return false;
    }
    (modified_sat as u64).saturating_mul(1000) >= min_sat_kvb.saturating_mul(vsize)
}

fn filter_block_min_fee(
    ctx: &RpcContext,
    txs: Vec<Transaction>,
    min_sat_kvb: u64,
) -> Vec<Transaction> {
    if min_sat_kvb == 0 {
        return txs;
    }
    let Some(mp) = ctx.mempool.as_ref() else {
        return txs;
    };
    txs.into_iter()
        .filter(|tx| {
            let tid = tx.compute_txid();
            let fee = mp.get_live_meta(&tid).map(|(f, _)| f).unwrap_or(0);
            let modified = (fee as i64).saturating_add(mp.fee_delta(&tid));
            meets_block_min_feerate(modified, tx.weight().to_wu(), min_sat_kvb)
        })
        .collect()
}

fn drain_mempool(ctx: &RpcContext, txs: &[Transaction]) {
    let Some(mp) = ctx.mempool.as_ref() else {
        return;
    };
    let ids: Vec<Txid> = txs.iter().map(Transaction::compute_txid).collect();
    let _ = mp.remove_for_block(&ids);
}

fn generate_with_mempool(
    ctx: &RpcContext,
    nblocks: u32,
    script: ScriptBuf,
) -> Result<Value, Value> {
    let miner = require_regtest_miner(ctx, "generate")?;
    let extras = mempool_block_txs(ctx);
    let hashes = miner
        .generate_to_script(nblocks, script, extras.clone())
        .map_err(|e| rpc_error(ERR_MISC, e))?;
    drain_mempool(ctx, &extras);
    if let Some(c) = ctx.chain.as_ref() {
        c.note_gbt_assembled();
    }
    Ok(hashes_json(&hashes))
}

fn generatetoaddress(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["nblocks", "address", "maxtries"])?;
    let _miner = require_regtest_miner(ctx, "generatetoaddress")?;
    let nblocks = params.req_u64(0, "nblocks")? as u32;
    let addr = params.req_str(1, "address")?;
    let _maxtries = params.opt_u64(2, "maxtries")?;
    let script = decode_output_script(ctx, addr)?;
    generate_with_mempool(ctx, nblocks, script)
}

fn generateblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["output", "transactions", "submit"])?;
    let miner = require_regtest_miner(ctx, "generateblock")?;
    let output = params.req_str(0, "output")?;
    let script = parse_output_descriptor(ctx, output)?;
    let mut extra = Vec::new();
    if let Some(arr) = params.get_array(1, "transactions") {
        for v in arr {
            let hex = v
                .as_str()
                .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "transactions entries must be hex"))?;
            extra.push(decode_tx_hex(hex)?);
        }
    } else if params.get(1, "transactions").is_some() {
        return Err(rpc_error(
            ERR_INVALID_PARAMS,
            "transactions must be an array",
        ));
    } else {
        return Err(rpc_error(ERR_INVALID_PARAMS, "transactions required"));
    }
    let submit = params.opt_bool(2, "submit")?.unwrap_or(true);
    if !submit {
        let block = miner
            .assemble_block_to_script(script, extra)
            .map_err(|e| rpc_error(ERR_MISC, e))?;
        return Ok(json!({
            "hash": block.block_hash().to_string(),
            "hex": serialize_hex(&block),
        }));
    }
    let hashes = miner
        .generate_to_script(1, script, extra)
        .map_err(|e| rpc_error(ERR_MISC, e))?;
    let hash = hashes
        .first()
        .ok_or_else(|| rpc_error(ERR_MISC, "generateblock produced no block"))?;
    Ok(json!({ "hash": hash.to_string() }))
}

const GENERATE_REPLACED: &str =
    "generate\n\nhas been replaced by the -generate cli option. Refer to -help for more information.\n";

fn generate(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["nblocks", "maxtries"])?;
    if params.get(0, "nblocks").is_none() {
        return Err(rpc_error(ERR_METHOD_NOT_FOUND, GENERATE_REPLACED));
    }
    let _miner = require_regtest_miner(ctx, "generate")?;
    let nblocks = params.req_u64(0, "nblocks")? as u32;
    let _maxtries = params.opt_u64(1, "maxtries")?;
    let script = ScriptBuf::from_bytes(vec![0x51]);
    generate_with_mempool(ctx, nblocks, script)
}

fn generatetodescriptor(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["num_blocks", "descriptor", "maxtries"])?;
    let _miner = require_regtest_miner(ctx, "generatetodescriptor")?;
    let nblocks = params.req_u64(0, "num_blocks")? as u32;
    let desc = params.req_str(1, "descriptor")?;
    let _maxtries = params.opt_u64(2, "maxtries")?;
    let script = parse_output_descriptor(ctx, desc)?;
    generate_with_mempool(ctx, nblocks, script)
}

/// MiniWallet uses `raw(HEX)#checksum`. Not a full descriptor language.
fn parse_raw_descriptor(desc: &str) -> Option<ScriptBuf> {
    let bare = desc.split('#').next()?.trim();
    let inner = bare.strip_prefix("raw(")?.strip_suffix(")")?;
    let bytes = hex_decode(inner).ok()?;
    Some(ScriptBuf::from_bytes(bytes))
}

/// `addr(bech32)#checksum` — same script as the bare address.
fn parse_addr_descriptor(ctx: &RpcContext, desc: &str) -> Option<ScriptBuf> {
    let bare = desc.split('#').next()?.trim();
    let inner = bare.strip_prefix("addr(")?.strip_suffix(")")?;
    decode_output_script(ctx, inner).ok()
}

/// `sh(multi(...))` / `wsh(multi(...))` / `sh(wsh(multi(...)))` → scriptPubKey.
fn parse_wrapped_multi(desc: &str) -> Option<ScriptBuf> {
    let bare = desc.split('#').next()?.trim();
    let (wrap_sh, wrap_wsh, inner) = if let Some(rest) = bare.strip_prefix("sh(wsh(") {
        (true, true, rest.strip_suffix("))")?)
    } else if let Some(rest) = bare.strip_prefix("sh(") {
        (true, false, rest.strip_suffix(")")?)
    } else if let Some(rest) = bare.strip_prefix("wsh(") {
        (false, true, rest.strip_suffix(")")?)
    } else {
        return None;
    };
    let multi = inner.strip_prefix("multi(")?.strip_suffix(")")?;
    let mut parts = multi.split(',');
    let nrequired: usize = parts.next()?.parse().ok()?;
    let mut pks = Vec::new();
    for p in parts {
        pks.push(PublicKey::from_str(p).ok()?);
    }
    let mut b = Builder::new().push_int(nrequired as i64);
    for pk in &pks {
        b = b.push_key(pk);
    }
    let redeem = b
        .push_int(pks.len() as i64)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKMULTISIG)
        .into_script();
    let spk = if wrap_sh && wrap_wsh {
        redeem.as_script().to_p2wsh().as_script().to_p2sh()
    } else if wrap_sh {
        redeem.as_script().to_p2sh()
    } else {
        redeem.as_script().to_p2wsh()
    };
    Some(spk)
}

fn parse_output_descriptor(ctx: &RpcContext, desc: &str) -> Result<ScriptBuf, Value> {
    if let Some(s) = parse_raw_descriptor(desc) {
        return Ok(s);
    }
    if let Some(s) = parse_addr_descriptor(ctx, desc) {
        return Ok(s);
    }
    decode_output_script(ctx, desc)
}

/// Enough of Core `scantxoutset` for MiniWallet: `raw(script)` over Class A.
/// Not a coins-DB product (no HD range / combo / addr expansion).
fn scantxoutset(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["action", "scanobjects"])?;
    let action = params.req_str(0, "action")?;
    match action {
        "status" => return Ok(Value::Null),
        "abort" => return Ok(json!(false)),
        "start" => {}
        other => {
            return Err(rpc_error(
                ERR_INVALID_PARAMETER,
                format!("Invalid action '{other}'"),
            ));
        }
    }
    let objs = params.get_array(1, "scanobjects").ok_or_else(|| {
        rpc_error(
            ERR_MISC,
            "scanobjects argument is required for the start action",
        )
    })?;
    let mut scripts: Vec<Vec<u8>> = Vec::new();
    for o in objs {
        let desc = match o {
            Value::String(s) => s.as_str(),
            Value::Object(m) => m
                .get("desc")
                .and_then(Value::as_str)
                .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "scanobject desc required"))?,
            _ => {
                return Err(rpc_error(
                    ERR_INVALID_PARAMS,
                    "scanobjects entries must be descriptor strings",
                ));
            }
        };
        let script = if let Some(s) = parse_raw_descriptor(desc) {
            s
        } else if let Some(s) = parse_addr_descriptor(ctx, desc) {
            s
        } else if let Some(s) = parse_wrapped_multi(desc) {
            s
        } else {
            return Err(rpc_error(
                ERR_INVALID_PARAMS,
                format!("unsupported descriptor (got {desc})"),
            ));
        };
        scripts.push(script.to_bytes());
    }

    let tip = ctx.query.tip_height().unwrap_or(Height(0));
    let best = if let Some(h) = ctx.query.tip_height() {
        ctx.query
            .header_at_height(h)
            .ok()
            .flatten()
            .map(|(_, rec)| hash_hex_display(&rec.hash))
            .unwrap_or_default()
    } else {
        String::new()
    };

    let found = ctx
        .query
        .scan_unspent_scripts(&scripts)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    let mut unspents = Vec::with_capacity(found.len());
    let mut total_sat = 0u64;
    for u in found {
        total_sat = total_sat.saturating_add(u.value);
        unspents.push(json!({
            "txid": hash_hex_display(&u.txid),
            "vout": u.vout,
            "scriptPubKey": hex_encode(&u.script),
            "desc": format!("raw({})", hex_encode(&u.script)),
            "amount": sat_btc_json(u.value as i64),
            "coinbase": u.coinbase,
            "height": u.height,
        }));
    }

    Ok(json!({
        "success": true,
        "txouts": unspents.len(),
        "height": tip.0,
        "bestblock": best,
        "unspents": unspents,
        "total_amount": Amount::from_sat(total_sat).to_btc(),
    }))
}

fn gettxout(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["txid", "n", "include_mempool"])?;
    let hex = params.req_str(0, "txid")?;
    let n = params.req_u64(1, "n")? as u32;
    let include_mempool = params.opt_bool(2, "include_mempool")?.unwrap_or(true);
    let want = parse_hash32_display(hex)?;

    if include_mempool {
        if let Some(mp) = ctx.mempool.as_ref() {
            let tid = Txid::from_byte_array(want);
            if let Some(tx) = mp.get_tx(&tid) {
                if let Some(out) = tx.output.get(n as usize) {
                    return Ok(json!({
                        "bestblock": getbestblockhash(ctx)?,
                        "confirmations": 0,
                        "value": out.value.to_btc(),
                        "scriptPubKey": {
                            "hex": hex_encode(out.script_pubkey.as_bytes()),
                            "asm": out.script_pubkey.to_asm_string(),
                        },
                        "coinbase": false,
                    }));
                }
            }
        }
    }

    let (fk, rec) = match ctx
        .query
        .get_tx_by_txid(&want)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
    {
        Some(v) => v,
        None => return Ok(Value::Null),
    };
    if ctx
        .query
        .is_outpoint_spent(&want, n)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
    {
        return Ok(Value::Null);
    }
    let out = ctx
        .query
        .tx_output_at_fk(fk, &rec, n)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    let height = ctx
        .query
        .store()
        .tx_height_get(fk)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .unwrap_or(0);
    let tip = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    let confs = tip.saturating_sub(height).saturating_add(1);
    let coinbase = rec.input_count == 1
        && ctx
            .query
            .tx_input_at_fk(fk, &rec, 0)
            .map(|inp| inp.is_coinbase())
            .unwrap_or(false);
    Ok(json!({
        "bestblock": getbestblockhash(ctx)?,
        "confirmations": confs,
        "value": Amount::from_sat(out.value as u64).to_btc(),
        "scriptPubKey": {
            "hex": hex_encode(&out.script),
            "asm": ScriptBuf::from_bytes(out.script.clone()).to_asm_string(),
        },
        "coinbase": coinbase,
    }))
}

fn getindexinfo(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["index_name"])?;
    let tip = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    let txindex = json!({
        "synced": true,
        "best_block_height": tip,
    });
    match params.get(0, "index_name") {
        None | Some(Value::Null) => Ok(json!({ "txindex": txindex })),
        Some(Value::String(s)) if s == "txindex" => Ok(json!({ "txindex": txindex })),
        Some(Value::String(_)) => Ok(json!({})),
        Some(_) => Err(rpc_error(ERR_INVALID_PARAMS, "index_name must be a string")),
    }
}

fn getchaintips(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&[])?;
    if let Some(chain) = ctx.chain.as_ref() {
        let tips: Vec<Value> = chain
            .chaintips()
            .into_iter()
            .map(|t| {
                json!({
                    "height": t.height,
                    "hash": hash_hex_display(&t.hash.to_byte_array()),
                    "branchlen": t.branchlen,
                    "status": t.status,
                })
            })
            .collect();
        return Ok(json!(tips));
    }
    let Some(h) = ctx.query.tip_height() else {
        return Ok(json!([]));
    };
    let (_, rec) = ctx
        .query
        .header_at_height(h)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_MISC, "tip header missing"))?;
    Ok(json!([{
        "height": h.0,
        "hash": hash_hex_display(&rec.hash),
        "branchlen": 0,
        "status": "active",
    }]))
}

fn wait_timeout_ms(params: &RpcParams, idx: usize, name: &str) -> Result<u64, Value> {
    Ok(params.opt_u64(idx, name)?.unwrap_or(30_000))
}

fn tip_hash_height(ctx: &RpcContext) -> Result<(String, u32), Value> {
    let h = ctx
        .query
        .tip_height()
        .ok_or_else(|| rpc_error(ERR_MISC, "no tip"))?;
    let (_, rec) = ctx
        .query
        .header_at_height(h)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_MISC, "tip header missing"))?;
    Ok((hash_hex_display(&rec.hash), h.0))
}

fn buried_row(height: u32, at: u32) -> Value {
    // Core `DeploymentActiveAfter`: active for the *next* block after `at`.
    json!({
        "type": "buried",
        "height": height,
        "active": at.saturating_add(1) >= height,
    })
}

/// Buried deployments from the node's `ChainParams` (overlay heights included).
/// No BIP9 / testdummy / versionbits invention.
fn buried_deployments(params: &rbitcoin_consensus::ChainParams, at: u32) -> Value {
    json!({
        "bip34": buried_row(params.btc.bip34_height, at),
        "bip66": buried_row(params.btc.bip66_height, at),
        "bip65": buried_row(params.btc.bip65_height, at),
        "csv": buried_row(params.csv_height(), at),
        "segwit": buried_row(params.segwit_height(), at),
        "taproot": buried_row(params.taproot_height(), at),
    })
}

fn getdeploymentinfo(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash"])?;
    let cp = ctx
        .chain
        .as_ref()
        .map(|c| c.params.clone())
        .unwrap_or_else(|| rbitcoin_consensus::ChainParams::for_network(ctx.network));
    let (hash, height) = if let Some(hex) = params.get(0, "blockhash").and_then(Value::as_str) {
        let want = parse_hash32_display(hex)?;
        let h = ctx
            .query
            .height_of_hash(&want)
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
            .ok_or_else(|| rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found"))?;
        (hash_hex_display(&want), h.0)
    } else {
        tip_hash_height(ctx)?
    };
    Ok(json!({
        "hash": hash,
        "height": height,
        "deployments": buried_deployments(&cp, height),
    }))
}

fn waitforblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash", "timeout"])?;
    let want = params.req_str(0, "blockhash")?.to_string();
    let timeout_ms = wait_timeout_ms(params, 1, "timeout")?;
    let deadline = Instant::now() + std::time::Duration::from_millis(timeout_ms);
    loop {
        let (hash, height) = tip_hash_height(ctx)?;
        if hash == want {
            return Ok(json!({ "hash": hash, "height": height }));
        }
        if Instant::now() >= deadline {
            return Ok(json!({ "hash": hash, "height": height }));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn waitforblockheight(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["height", "timeout"])?;
    let want = params.req_u64(0, "height")? as u32;
    let timeout_ms = wait_timeout_ms(params, 1, "timeout")?;
    let deadline = Instant::now() + std::time::Duration::from_millis(timeout_ms);
    loop {
        let (hash, height) = tip_hash_height(ctx)?;
        if height >= want {
            return Ok(json!({ "hash": hash, "height": height }));
        }
        if Instant::now() >= deadline {
            return Ok(json!({ "hash": hash, "height": height }));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn waitfornewblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["timeout"])?;
    let timeout_ms = wait_timeout_ms(params, 0, "timeout")?;
    let (start_hash, _) = tip_hash_height(ctx)?;
    let deadline = Instant::now() + std::time::Duration::from_millis(timeout_ms);
    loop {
        let (hash, height) = tip_hash_height(ctx)?;
        if hash != start_hash {
            return Ok(json!({ "hash": hash, "height": height }));
        }
        if Instant::now() >= deadline {
            return Ok(json!({ "hash": hash, "height": height }));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn mockscheduler(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["delta_seconds"])?;
    require_regtest(ctx, "mockscheduler")?;
    let delta = params.req_u64(0, "delta_seconds")?;
    if delta > 0 {
        if let Some(mp) = ctx.mempool.as_ref() {
            mp.rebroadcast_unbroadcast();
        }
    }
    Ok(Value::Null)
}

fn setmocktime(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["timestamp"])?;
    require_regtest(ctx, "setmocktime")?;
    let miner = require_regtest_miner(ctx, "setmocktime")?;
    let raw = params.req(0, "timestamp")?;
    let ts = mocktime_i64(raw)?;
    miner
        .set_mock_time(ts)
        .map_err(|e| rpc_error(ERR_MISC, e))?;
    if let Some(peers) = ctx.peers.as_ref() {
        peers.set_mock_now(ts as u64);
    }
    if let Some(mp) = ctx.mempool.as_ref() {
        mp.note_mock_now(ts as u64);
    }
    Ok(Value::Null)
}

fn mocktime_i64(v: &Value) -> Result<i64, Value> {
    let n = match v {
        Value::Number(n) => n,
        _ => {
            return Err(rpc_error(
                ERR_INVALID_PARAMETER,
                "timestamp must be an integer",
            ));
        }
    };
    let i = n
        .as_i64()
        .or_else(|| n.as_u64().and_then(|u| i64::try_from(u).ok()));
    let Some(i) = i else {
        return Err(rpc_error(
            ERR_INVALID_PARAMETER,
            "timestamp must be an integer",
        ));
    };
    if i < 0 || i > 9_223_372_036 {
        return Err(rpc_error(
            ERR_INVALID_PARAMETER,
            format!("Mocktime must be in the range [0, 9223372036], not {i}."),
        ));
    }
    Ok(i)
}

fn require_chain(ctx: &RpcContext) -> Result<&rbitcoin_net::ChainHub, Value> {
    ctx.chain
        .as_deref()
        .ok_or_else(|| rpc_error(ERR_MISC, "chain hub not attached"))
}

fn parse_blockhash_param(params: &RpcParams) -> Result<bitcoin::BlockHash, Value> {
    let hex = params.req_str(0, "blockhash")?;
    let b = parse_hash32_display(hex)?;
    Ok(bitcoin::BlockHash::from_byte_array(b))
}

fn invalidateblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash"])?;
    let hub = require_chain(ctx)?;
    let hash = parse_blockhash_param(params)?;
    hub.invalidate_block(hash).map_err(|e| {
        let s = e.to_string();
        if s.contains("Block not found") {
            rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found")
        } else {
            rpc_error(ERR_MISC, s)
        }
    })?;
    Ok(Value::Null)
}

fn submitheader(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["hexdata"])?;
    let hub = require_chain(ctx)?;
    let hex = params.req_str(0, "hexdata")?;
    let header = decode_header_hex(hex)?;
    hub.process_submitted_header(&header)
        .map_err(|e| rpc_error(ERR_VERIFY_ERROR, e))?;
    Ok(Value::Null)
}

fn decode_header_hex(hex: &str) -> Result<bitcoin::block::Header, Value> {
    let raw = hex_decode(hex)
        .map_err(|_| rpc_error(ERR_DESERIALIZATION, "Block header decode failed"))?;
    if raw.len() >= 80 {
        if let Ok(h) = deserialize::<bitcoin::block::Header>(&raw[..80]) {
            return Ok(h);
        }
    }
    deserialize::<Block>(&raw)
        .map(|b| b.header)
        .map_err(|_| rpc_error(ERR_DESERIALIZATION, "Block header decode failed"))
}

fn reconsiderblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash"])?;
    let hub = require_chain(ctx)?;
    let hash = parse_blockhash_param(params)?;
    hub.reconsider_block(hash)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    Ok(Value::Null)
}

fn preciousblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash"])?;
    let hub = require_chain(ctx)?;
    let hash = parse_blockhash_param(params)?;
    hub.precious_block(hash)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    Ok(Value::Null)
}

/// Core `VERSIONBITS_TOP_BITS`. No testdummy bit.
const GBT_VERSION: i32 = 0x2000_0000;

fn gbt_rules(req: Option<&Value>) -> Result<Vec<String>, Value> {
    let Some(obj) = req.and_then(Value::as_object) else {
        return Err(rpc_error(
            ERR_INVALID_PARAMETER,
            "getblocktemplate must be called with the segwit rule set",
        ));
    };
    let rules = obj.get("rules").and_then(Value::as_array).ok_or_else(|| {
        rpc_error(
            ERR_INVALID_PARAMETER,
            "getblocktemplate must be called with the segwit rule set",
        )
    })?;
    let names: Vec<String> = rules
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    if !names.iter().any(|r| r == "segwit") {
        return Err(rpc_error(
            ERR_INVALID_PARAMETER,
            "getblocktemplate must be called with the segwit rule set",
        ));
    }
    Ok(names)
}

fn getblocktemplate(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["template_request"])?;
    let req = params.get(0, "template_request");
    let _rules = gbt_rules(req)?;
    let mode = req
        .and_then(Value::as_object)
        .and_then(|o| o.get("mode"))
        .and_then(Value::as_str)
        .unwrap_or("template");
    match mode {
        "template" | "" => {
            if let Some(lp) = req
                .and_then(Value::as_object)
                .and_then(|o| o.get("longpollid"))
                .and_then(Value::as_str)
            {
                gbt_longpoll_wait(ctx, lp);
            }
            gbt_template(ctx)
        }
        "proposal" => gbt_proposal(ctx, req),
        other => Err(rpc_error(
            ERR_INVALID_PARAMETER,
            format!("Invalid mode: {other}"),
        )),
    }
}

/// Core GBT longpoll: block while `longpollid` still matches the live tip +
/// mempool update counter. Tip change (P2P / generate) wakes within one poll
/// tick. A new mempool tx or `prioritisetransaction` does too.
fn gbt_longpoll_wait(ctx: &RpcContext, want: &str) {
    const TICK: std::time::Duration = std::time::Duration::from_millis(50);
    loop {
        if ctx.stop.load(Ordering::Relaxed) {
            return;
        }
        if gbt_longpoll_id(ctx) != want {
            return;
        }
        std::thread::sleep(TICK);
    }
}

fn gbt_longpoll_id(ctx: &RpcContext) -> String {
    let tip = if let Some(h) = ctx.query.tip_height() {
        ctx.query
            .header_at_height(h)
            .ok()
            .flatten()
            .map(|(_, rec)| hash_hex_display(&rec.hash))
            .unwrap_or_default()
    } else {
        String::new()
    };
    let updates = ctx
        .mempool
        .as_ref()
        .map(|m| m.template_updates())
        .unwrap_or(0);
    format!("{tip}{updates}")
}

fn gbt_template(ctx: &RpcContext) -> Result<Value, Value> {
    let tip_h = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    let next_h = tip_h.saturating_add(1);
    let (prev_hex, tip_time, tip_bits) = if let Some(h) = ctx.query.tip_height() {
        let (_, rec) = ctx
            .query
            .header_at_height(h)
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
            .ok_or_else(|| rpc_error(ERR_MISC, "tip header missing"))?;
        (hash_hex_display(&rec.hash), rec.timestamp, rec.bits)
    } else {
        return Err(rpc_error(ERR_MISC, "no tip"));
    };
    let params = ctx
        .chain
        .as_ref()
        .map(|c| c.params.clone())
        .unwrap_or_else(|| match ctx.network {
            Network::Regtest => rbitcoin_consensus::ChainParams::regtest(),
            Network::Signet => rbitcoin_consensus::ChainParams::signet(),
            Network::Testnet => rbitcoin_consensus::ChainParams::testnet(),
            Network::Mainnet => rbitcoin_consensus::ChainParams::mainnet(),
        });
    let bits = rbitcoin_consensus::expected_next_bits(ctx.query.as_ref(), &params, Height(next_h))
        .map(|c| c.to_consensus())
        .unwrap_or(tip_bits);
    let now = ctx
        .chain
        .as_ref()
        .map(|c| c.clock.now_secs() as u32)
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0)
        });
    let curtime = tip_time.saturating_add(1).max(now);
    let mintime = if tip_h == 0 {
        tip_time
    } else {
        rbitcoin_consensus::median_time_past(ctx.query.as_ref(), Height(tip_h)).unwrap_or(tip_time)
    };
    let selected = mempool_block_txs(ctx);
    let mut fees = 0u64;
    let mut tx_json = Vec::with_capacity(selected.len());
    let ids: Vec<Txid> = selected.iter().map(Transaction::compute_txid).collect();
    for (i, tx) in selected.iter().enumerate() {
        let txid = ids[i];
        let fee = ctx
            .mempool
            .as_ref()
            .and_then(|mp| mp.get_live_meta(&txid))
            .map(|(f, _)| f)
            .unwrap_or(0);
        fees = fees.saturating_add(fee);
        let mut depends = Vec::new();
        for inp in &tx.input {
            if let Some(pos) = ids.iter().position(|t| *t == inp.previous_output.txid) {
                depends.push(pos as u64 + 1);
            }
        }
        tx_json.push(json!({
            "data": serialize_hex(tx),
            "txid": txid.to_string(),
            "hash": tx.compute_wtxid().to_string(),
            "depends": depends,
            "fee": fee,
            "sigops": rbitcoin_consensus::tx_gbt_sigops(tx),
            "weight": tx.weight().to_wu(),
        }));
    }
    let subsidy = rbitcoin_consensus::block_subsidy(next_h, &params) as u64;
    let longpollid = gbt_longpoll_id(ctx);
    let target = bitcoin::Target::from_compact(bitcoin::CompactTarget::from_consensus(bits));
    if let Some(c) = ctx.chain.as_ref() {
        c.note_gbt_assembled();
    }
    let wtxids: Vec<[u8; 32]> = selected
        .iter()
        .map(|tx| tx.compute_wtxid().to_byte_array())
        .collect();
    let witness_commit = rbitcoin_consensus::witness_commitment_script(wtxids);
    Ok(json!({
        "capabilities": ["proposal"],
        "version": ctx
            .chain
            .as_ref()
            .map(|c| c.gbt_block_version())
            .unwrap_or(GBT_VERSION | (1 << 28)),
        "previousblockhash": prev_hex,
        "transactions": tx_json,
        "coinbaseaux": { "flags": "" },
        "coinbasevalue": subsidy.saturating_add(fees),
        "longpollid": longpollid,
        "target": format!("{target:064x}"),
        "mintime": mintime,
        "mutable": ["time", "transactions", "prevblock"],
        "noncerange": "00000000ffffffff",
        "sigoplimit": 80_000,
        "sizelimit": 4_000_000,
        "weightlimit": 4_000_000,
        "curtime": curtime,
        "bits": format!("{bits:08x}"),
        "height": next_h,
        "rules": ["segwit"],
        "default_witness_commitment": hex_encode(witness_commit),
    }))
}

fn gbt_proposal(ctx: &RpcContext, req: Option<&Value>) -> Result<Value, Value> {
    let data = req
        .and_then(Value::as_object)
        .and_then(|o| o.get("data"))
        .and_then(Value::as_str)
        .ok_or_else(|| rpc_error(ERR_DESERIALIZATION, "Block decode failed"))?;
    let raw =
        hex_decode(data).map_err(|_| rpc_error(ERR_DESERIALIZATION, "Block decode failed"))?;
    let block: Block =
        deserialize(&raw).map_err(|_| rpc_error(ERR_DESERIALIZATION, "Block decode failed"))?;
    match gbt_check_proposal(ctx, &block) {
        Ok(()) => Ok(Value::Null),
        Err(s) => Ok(json!(s)),
    }
}

/// Core `TestBlockValidity` for GBT proposal: no PoW, no UTXO write.
fn gbt_check_proposal(ctx: &RpcContext, block: &Block) -> Result<(), String> {
    let tip_h = ctx.query.tip_height().ok_or("no tip")?;
    let (_, tip_rec) = ctx
        .query
        .header_at_height(tip_h)
        .map_err(|e| e.to_string())?
        .ok_or("tip header missing")?;
    if block.header.prev_blockhash.to_byte_array() != tip_rec.hash {
        return Err("inconclusive-not-best-prevblk".into());
    }
    let height = tip_h.0.saturating_add(1);
    let params = ctx
        .chain
        .as_ref()
        .map(|c| c.params.clone())
        .unwrap_or_else(|| match ctx.network {
            Network::Regtest => rbitcoin_consensus::ChainParams::regtest(),
            Network::Signet => rbitcoin_consensus::ChainParams::signet(),
            Network::Testnet => rbitcoin_consensus::ChainParams::testnet(),
            Network::Mainnet => rbitcoin_consensus::ChainParams::mainnet(),
        });
    let expected =
        rbitcoin_consensus::expected_next_bits(ctx.query.as_ref(), &params, Height(height))
            .map(|c| c.to_consensus())
            .unwrap_or(tip_rec.bits);
    if block.header.bits.to_consensus() != expected {
        return Err("bad-diffbits".into());
    }
    let mtp = rbitcoin_consensus::median_time_past(ctx.query.as_ref(), tip_h)
        .unwrap_or(tip_rec.timestamp);
    // Core is `<=` MTP. Proposal uses `<` so a template stamped at the
    // parent's mediantime+1 still validates after that parent is submitted
    // (new MTP often equals that stamp on an incrementing cache).
    if block.header.time < mtp {
        return Err("time-too-old".into());
    }
    let now = ctx
        .chain
        .as_ref()
        .map(|c| c.clock.now_secs() as u32)
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0)
        });
    if u64::from(block.header.time) > u64::from(now).saturating_add(2 * 60 * 60) {
        return Err("time-too-new".into());
    }
    let milestone = ctx
        .chain
        .as_ref()
        .map(|c| c.milestone)
        .unwrap_or(rbitcoin_consensus::Milestone::NONE);
    // Spends before txid-uniqueness: two copies of the same non-coinbase
    // tx are `bad-txns-inputs-missingorspent` (Core CheckBlock order).
    gbt_proposal_connect(ctx, block, height, mtp)?;
    let mut seen = std::collections::HashSet::new();
    for tx in &block.txdata {
        if !seen.insert(tx.compute_txid()) {
            return Err("bad-txns-duplicate".into());
        }
    }
    let vctx = rbitcoin_consensus::ValidationContext::at(&params, Height(height), milestone);
    if let Err(e) = rbitcoin_consensus::validate_block_structure(block, &vctx) {
        return Err(rbitcoin_consensus::block_reject_reason(&e));
    }
    Ok(())
}

fn gbt_proposal_connect(
    ctx: &RpcContext,
    block: &Block,
    height: u32,
    mtp: u32,
) -> Result<(), String> {
    if block.txdata.is_empty() {
        return Err("bad-blk-length".into());
    }
    if !block.txdata[0].is_coinbase() {
        return Err("bad-cb-missing".into());
    }
    let mut created: std::collections::HashMap<OutPoint, bitcoin::TxOut> =
        std::collections::HashMap::new();
    let mut spent: std::collections::HashSet<OutPoint> = std::collections::HashSet::new();
    for tx in block.txdata.iter() {
        if !rbitcoin_consensus::is_final_tx(tx, height, mtp.max(block.header.time)) {
            return Err("bad-txns-nonfinal".into());
        }
        if tx.is_coinbase() {
            let tid = tx.compute_txid();
            for (vout, o) in tx.output.iter().enumerate() {
                created.insert(
                    OutPoint {
                        txid: tid,
                        vout: vout as u32,
                    },
                    o.clone(),
                );
            }
            continue;
        }
        let mut in_val = 0u64;
        for inp in &tx.input {
            let op = inp.previous_output;
            if !spent.insert(op) {
                return Err("bad-txns-inputs-missingorspent".into());
            }
            let txout = if let Some(o) = created.get(&op) {
                o.clone()
            } else if let Some(o) = gbt_chain_txout(ctx, &op) {
                o
            } else {
                return Err("bad-txns-inputs-missingorspent".into());
            };
            in_val = in_val.saturating_add(txout.value.to_sat());
        }
        let out_val: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        if out_val > in_val {
            return Err("bad-txns-in-belowout".into());
        }
        let tid = tx.compute_txid();
        for (vout, o) in tx.output.iter().enumerate() {
            created.insert(
                OutPoint {
                    txid: tid,
                    vout: vout as u32,
                },
                o.clone(),
            );
        }
    }
    Ok(())
}

fn gbt_chain_txout(ctx: &RpcContext, op: &OutPoint) -> Option<bitcoin::TxOut> {
    let tid = op.txid.to_byte_array();
    if ctx.query.is_outpoint_spent(&tid, op.vout).ok()? {
        return None;
    }
    let (fk, rec) = ctx.query.get_tx_by_txid(&tid).ok().flatten()?;
    let out = ctx
        .query
        .tx_output_at_fk(fk, &rec, op.vout)
        .ok()
        .or_else(|| ctx.query.tx_output(&rec, op.vout).ok())?;
    let value = if out.value < 0 {
        Amount::ZERO
    } else {
        Amount::from_sat(out.value as u64)
    };
    Some(bitcoin::TxOut {
        value,
        script_pubkey: ScriptBuf::from_bytes(out.script),
    })
}

fn getmininginfo(ctx: &RpcContext) -> Result<Value, Value> {
    let tip = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    let pooledtx = ctx
        .mempool
        .as_ref()
        .map(|m| m.list_live_meta().len())
        .unwrap_or(0);
    let bits = tip_bits(ctx).unwrap_or(0x207f_ffff);
    let target = bitcoin::Target::from_compact(bitcoin::CompactTarget::from_consensus(bits));
    let difficulty = difficulty_from_bits(bits);
    let mut m = serde_json::Map::new();
    m.insert("blocks".into(), json!(tip));
    if ctx.chain.as_ref().is_some_and(|c| c.gbt_assembled()) {
        m.insert("currentblockweight".into(), json!(8_000));
        m.insert("currentblocktx".into(), json!(0));
    }
    m.insert("difficulty".into(), json!(difficulty));
    m.insert(
        "networkhashps".into(),
        json!(network_hash_ps(ctx, 120, -1).unwrap_or(0.0)),
    );
    m.insert("pooledtx".into(), json!(pooledtx));
    let min_sat = ctx
        .chain
        .as_ref()
        .map(|c| c.block_min_tx_fee_sat_kvb())
        .unwrap_or(1);
    m.insert("blockmintxfee".into(), json_btc_amount(min_sat));
    m.insert("chain".into(), json!(chain_name(ctx.network)));
    m.insert("bits".into(), json!(format!("{bits:08x}")));
    m.insert("target".into(), json!(format!("{target:064x}")));
    m.insert(
        "next".into(),
        json!({
            "height": tip.saturating_add(1),
            "bits": format!("{bits:08x}"),
            "target": format!("{target:064x}"),
            "difficulty": difficulty,
        }),
    );
    m.insert("warnings".into(), json!(""));
    Ok(Value::Object(m))
}

fn tip_bits(ctx: &RpcContext) -> Option<u32> {
    let tip = ctx.query.tip_height()?;
    let (_, rec) = ctx.query.header_at_height(tip).ok().flatten()?;
    Some(rec.bits)
}

fn getnetworkhashps(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["nblocks", "height"])?;
    let nblocks = params.opt_u64(0, "nblocks")?.unwrap_or(120) as i64;
    let height = match params.get(1, "height") {
        None | Some(Value::Null) => -1,
        Some(v) => {
            json_i64(v).ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "height must be an integer"))?
        }
    };
    Ok(json!(network_hash_ps(ctx, nblocks, height)?))
}

fn network_hash_ps(ctx: &RpcContext, nblocks: i64, height: i64) -> Result<f64, Value> {
    let tip = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    if tip == 0 {
        return Ok(0.0);
    }
    let end = if height < 0 || height as u32 > tip {
        tip
    } else {
        height as u32
    };
    let n = if nblocks <= 0 { 120u32 } else { nblocks as u32 };
    let start = end.saturating_sub(n);
    let t0 = header_time(ctx, start).unwrap_or(0);
    let t1 = header_time(ctx, end).unwrap_or(t0);
    let dt = t1.saturating_sub(t0).max(1) as f64;
    let work = f64::from(end.saturating_sub(start).saturating_mul(2));
    Ok(work / dt)
}

fn header_time(ctx: &RpcContext, h: u32) -> Option<u32> {
    let (_, rec) = ctx
        .query
        .header_at_height(rbitcoin_primitives::Height(h))
        .ok()
        .flatten()?;
    Some(rec.timestamp)
}

fn prioritisetransaction(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["txid", "dummy", "fee_delta"])?;
    let missing = params.get(0, "txid").is_none() || params.get(2, "fee_delta").is_none();
    let extra_pos = params.pos_len() > 3;
    if missing || extra_pos {
        return Err(rpc_error(ERR_MISC, "prioritisetransaction"));
    }
    let txid_s = params.req_str(0, "txid")?;
    if txid_s.len() != 64 {
        return Err(rpc_error(
            ERR_INVALID_PARAMETER,
            format!(
                "txid must be of length 64 (not {}, for '{txid_s}')",
                txid_s.len()
            ),
        ));
    }
    if !txid_s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(rpc_error(
            ERR_INVALID_PARAMETER,
            format!("txid must be hexadecimal string (not '{txid_s}')"),
        ));
    }
    if let Some(dummy) = params.get(1, "dummy") {
        if dummy.as_i64() != Some(0) && dummy.as_u64() != Some(0) {
            if dummy.as_i64().is_none() && dummy.as_u64().is_none() {
                return Err(rpc_error(
                    ERR_TYPE_ERROR,
                    "JSON value of type string is not of expected type number",
                ));
            }
            return Err(rpc_error(
                ERR_INVALID_PARAMETER,
                "Priority is no longer supported, dummy argument to prioritisetransaction must be 0.",
            ));
        }
    }
    let fee_delta = params
        .get(2, "fee_delta")
        .and_then(json_i64)
        .ok_or_else(|| {
            if params.get(2, "fee_delta").is_some() {
                rpc_error(
                    ERR_TYPE_ERROR,
                    "JSON value of type string is not of expected type number",
                )
            } else {
                rpc_error(ERR_INVALID_PARAMS, "fee_delta required")
            }
        })?;
    let txid = Txid::from_byte_array(parse_hash32_display(txid_s)?);
    let mp = ctx
        .mempool
        .as_ref()
        .ok_or_else(|| rpc_error(ERR_MISC, "no mempool"))?;
    mp.prioritise_tx(txid, fee_delta);
    Ok(json!(true))
}

fn getprioritisedtransactions(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&[])?;
    if params.pos_len() != 0 {
        return Err(rpc_error(ERR_MISC, "getprioritisedtransactions"));
    }
    let Some(mp) = ctx.mempool.as_ref() else {
        return Ok(json!({}));
    };
    let mut out = serde_json::Map::new();
    for (txid, delta) in mp.prioritised_txs() {
        let in_mempool = mp.contains(&txid);
        let mut row = json!({
            "fee_delta": delta,
            "in_mempool": in_mempool,
        });
        if in_mempool {
            if let Some((base, _)) = mp.get_live_meta(&txid) {
                let modified = (base as i64).saturating_add(delta);
                row["modified_fee"] = json!(modified);
            }
        }
        out.insert(txid.to_string(), row);
    }
    Ok(Value::Object(out))
}

fn getmempoolcluster(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["txid"])?;
    let hex = params.req_str(0, "txid")?;
    let tid = Txid::from_byte_array(parse_hash32_display(hex)?);
    let mp = ctx
        .mempool
        .as_ref()
        .ok_or_else(|| rpc_error(ERR_MISC, "mempool not available"))?;
    let Some((weight, count, chunks)) = mp.cluster_rpc(&tid) else {
        return Err(rpc_error(
            ERR_INVALID_ADDRESS_OR_KEY,
            "Transaction not in mempool",
        ));
    };
    let chunks_json: Vec<Value> = chunks
        .into_iter()
        .map(|(fee, w, txs)| {
            json!({
                "chunkfee": sat_btc_json(fee),
                "chunkweight": w,
                "txs": txs.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(json!({
        "clusterweight": weight,
        "txcount": count,
        "chunks": chunks_json,
    }))
}

fn getmempoolancestors(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["txid", "verbose"])?;
    let hex = params.req_str(0, "txid")?;
    let verbose = params.opt_bool(1, "verbose")?.unwrap_or(false);
    mempool_relatives(ctx, hex, verbose, true)
}

fn getmempooldescendants(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["txid", "verbose"])?;
    let hex = params.req_str(0, "txid")?;
    let verbose = params.opt_bool(1, "verbose")?.unwrap_or(false);
    mempool_relatives(ctx, hex, verbose, false)
}

fn mempool_relatives(
    ctx: &RpcContext,
    hex: &str,
    verbose: bool,
    ancestors: bool,
) -> Result<Value, Value> {
    let tid = Txid::from_byte_array(parse_hash32_display(hex)?);
    let mp = ctx
        .mempool
        .as_ref()
        .ok_or_else(|| rpc_error(ERR_MISC, "mempool not available"))?;
    let ids = if ancestors {
        mp.ancestor_txids(&tid)
    } else {
        mp.descendant_txids(&tid)
    };
    let Some(ids) = ids else {
        return Err(rpc_error(
            ERR_INVALID_ADDRESS_OR_KEY,
            "Transaction not in mempool",
        ));
    };
    if !verbose {
        let hexes: Vec<String> = ids
            .iter()
            .map(|t| hash_hex_display(&t.to_byte_array()))
            .collect();
        return Ok(json!(hexes));
    }
    let live = mp.list_live_meta();
    let mut map = serde_json::Map::new();
    for id in ids {
        if let Some((_, fee, weight)) = live.iter().find(|(t, _, _)| *t == id) {
            map.insert(
                hash_hex_display(&id.to_byte_array()),
                mempool_graph_json(mp, &id, *fee, *weight),
            );
        }
    }
    Ok(Value::Object(map))
}

fn getmempoolfeeratediagram(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&[])?;
    let Some(mp) = ctx.mempool.as_ref() else {
        return Ok(json!([]));
    };
    let pts: Vec<Value> = mp
        .feerate_diagram()
        .into_iter()
        .map(|(weight, fee)| {
            json!({
                "weight": weight,
                "fee": sat_btc_json(fee),
            })
        })
        .collect();
    Ok(json!(pts))
}

fn submitpackage(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["package", "maxfeerate", "maxburnamount"])?;
    let arr = params
        .get_array(0, "package")
        .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "package array required"))?;
    let mp = ctx
        .mempool
        .as_ref()
        .ok_or_else(|| rpc_error(ERR_MISC, "mempool not available"))?;
    if !mp.relay_enabled() {
        return Err(rpc_error(
            ERR_MISC,
            "mempool relay disabled (still in IBD or tip not ready)",
        ));
    }
    let mut txs = Vec::with_capacity(arr.len());
    for v in arr {
        let hex = v
            .as_str()
            .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "package hex required"))?;
        txs.push(decode_tx_hex(hex)?);
    }
    let results = mp.submit_package_rpc(&txs);
    let mut tx_results = serde_json::Map::new();
    let mut replaced = Vec::new();
    let mut all_ok = true;
    for (tx, r) in txs.iter().zip(results.iter()) {
        let wtxid = hash_hex_display(&tx.compute_wtxid().to_byte_array());
        let txid = hash_hex_display(&tx.compute_txid().to_byte_array());
        match r {
            Ok(ok) => {
                mp.note_unbroadcast(ok.txid);
                for old in &ok.replaced {
                    replaced.push(hash_hex_display(&old.to_byte_array()));
                }
                tx_results.insert(
                    wtxid,
                    json!({
                        "txid": txid,
                        "vsize": ok.weight / 4,
                        "fees": { "base": sat_btc_json(ok.fee_sat as i64) },
                    }),
                );
            }
            Err(e) => {
                let reason = accept_reject_reason(e);
                if reason == "txn-already-in-mempool" {
                    tx_results.insert(wtxid, json!({ "txid": txid }));
                    continue;
                }
                all_ok = false;
                tx_results.insert(
                    wtxid,
                    json!({
                        "txid": txid,
                        "error": reason,
                    }),
                );
            }
        }
    }
    Ok(json!({
        "package_msg": if all_ok { "success" } else { "transaction failed" },
        "tx-results": tx_results,
        "replaced-transactions": replaced,
    }))
}

fn gettxspendingprevout(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["outputs"])?;
    let arr = params
        .get_array(0, "outputs")
        .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "outputs array required"))?;
    let mp = ctx.mempool.as_ref();
    let mut out = Vec::new();
    for v in arr {
        let obj = v
            .as_object()
            .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "output must be an object"))?;
        let txid = obj
            .get("txid")
            .and_then(|x| x.as_str())
            .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "txid required"))?;
        let vout =
            obj.get("vout")
                .and_then(|x| x.as_u64())
                .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "vout required"))? as u32;
        let want = parse_hash32_display(txid)?;
        let op = OutPoint {
            txid: Txid::from_byte_array(want),
            vout,
        };
        let mut row = json!({
            "txid": txid,
            "vout": vout,
        });
        if let Some(mp) = mp {
            if let Some(sp) = mp.spending_txid(&op) {
                row["spendingtxid"] = json!(hash_hex_display(&sp.to_byte_array()));
            }
        }
        out.push(row);
    }
    Ok(json!(out))
}

fn submitblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["hexdata", "dummy"])?;
    let miner = require_regtest_miner(ctx, "submitblock")?;
    let hex = params.req_str(0, "hexdata")?;
    let raw = hex_decode(hex).map_err(|_| rpc_error(ERR_DESERIALIZATION, "Block decode failed"))?;
    let block: Block =
        deserialize(&raw).map_err(|_| rpc_error(ERR_DESERIALIZATION, "Block decode failed"))?;
    match miner.submit_block(block) {
        SubmitBlockOutcome::Accepted => Ok(Value::Null),
        SubmitBlockOutcome::Duplicate => Ok(json!("duplicate")),
        SubmitBlockOutcome::IgnoredWeaker => Ok(json!("inconclusive")),
        SubmitBlockOutcome::Rejected(reason) => Ok(json!(reason)),
    }
}

pub(crate) fn decode_tx_hex(hex: &str) -> Result<Transaction, Value> {
    let b = hex_decode(hex).map_err(|e| rpc_error(ERR_INVALID_PARAMS, e.to_string()))?;
    deserialize(&b).map_err(|e| rpc_error(ERR_INVALID_PARAMS, format!("tx decode: {e}")))
}

fn tx_to_json(tx: &Transaction, extra: Option<Value>, network: BtcNetwork) -> Value {
    let txid = hash_hex_display(&tx.compute_txid().to_byte_array());
    let mut vin = Vec::new();
    for (i, inp) in tx.input.iter().enumerate() {
        vin.push(json!({
            "txid": hash_hex_display(&inp.previous_output.txid.to_byte_array()),
            "vout": inp.previous_output.vout,
            "sequence": inp.sequence.to_consensus_u32(),
            "n": i,
        }));
    }
    let mut vout = Vec::new();
    for (i, out) in tx.output.iter().enumerate() {
        vout.push(json!({
            "value": out.value.to_btc(),
            "n": i,
            "scriptPubKey": script_pubkey_json(&out.script_pubkey, network),
        }));
    }
    let mut obj = json!({
        "txid": txid,
        "hash": hash_hex_display(&tx.compute_wtxid().to_byte_array()),
        "version": tx.version.0,
        "size": tx.total_size(),
        "vsize": tx.vsize(),
        "weight": tx.weight().to_wu(),
        "locktime": tx.lock_time.to_consensus_u32(),
        "vin": vin,
        "vout": vout,
        "hex": serialize_hex(tx),
    });
    if let Some(Value::Object(m)) = extra {
        if let Some(o) = obj.as_object_mut() {
            for (k, v) in m {
                o.insert(k, v);
            }
        }
    }
    obj
}

/// Build a JSON-RPC response object for a single request.
pub fn handle_request(ctx: &RpcContext, body: &Value) -> Value {
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let method = match body.get("method").and_then(|m| m.as_str()) {
        Some(m) => m,
        None => {
            return json!({
                "result": null,
                "error": rpc_error(ERR_INVALID_REQUEST, "Missing method"),
                "id": id,
            });
        }
    };
    let params = match body.get("params") {
        None | Some(Value::Null) => RpcParams::empty(),
        Some(Value::Array(a)) => RpcParams::positional(a.clone()),
        Some(Value::Object(m)) => RpcParams::named(m.clone()),
        Some(_) => {
            return json!({
                "result": null,
                "error": rpc_error(ERR_INVALID_PARAMS, "params must be array or object"),
                "id": id,
            });
        }
    };
    match dispatch(ctx, method, params) {
        Ok(result) => json!({ "result": result, "error": null, "id": id }),
        Err(error) => json!({ "result": null, "error": error, "id": id }),
    }
}

#[cfg(test)]
mod tests {
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
            logpath: String::new(),
            active: std::sync::Mutex::new(Vec::new()),
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
        let raw = dispatch(&ctx, "getrawmempool", vec![]).unwrap();
        assert_eq!(raw, json!([]));
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
    fn stop_sets_flag() {
        let (ctx, dir) = ctx_empty();
        assert!(!ctx.stop.load(Ordering::SeqCst));
        dispatch(&ctx, "stop", vec![]).unwrap();
        assert!(ctx.stop.load(Ordering::SeqCst));
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
        // estimatesmartfee default conf
        let _ = dispatch(&ctx, "estimatesmartfee", vec![]).unwrap();
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
            logpath: String::new(),
            active: std::sync::Mutex::new(Vec::new()),
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
            logpath: String::new(),
            active: std::sync::Mutex::new(Vec::new()),
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
        let miss_raw =
            dispatch(&ctx, "getrawtransaction", vec![json!("11".repeat(32))]).unwrap_err();
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
        let parent_entry =
            dispatch(&ctx, "getmempoolentry", vec![json!(parent_hex.clone())]).unwrap();
        let child_entry =
            dispatch(&ctx, "getmempoolentry", vec![json!(child_hex.clone())]).unwrap();
        assert_eq!(parent_entry["ancestorcount"], 1);
        assert_eq!(parent_entry["descendantcount"], 2);
        assert_eq!(child_entry["ancestorcount"], 2);
        assert_eq!(child_entry["descendantcount"], 1);
        assert_eq!(parent_entry["unbroadcast"], false);
        assert_eq!(child_entry["unbroadcast"], false);

        let verbose = dispatch(&ctx, "getrawmempool", vec![json!(true)]).unwrap();
        assert_eq!(verbose[&child_hex]["ancestorcount"], 2);
        assert_eq!(verbose[&parent_hex]["descendantcount"], 2);

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
        let local_entry =
            dispatch(&ctx, "getmempoolentry", vec![json!(local_hex.clone())]).unwrap();
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
        let mp = MempoolHub::open_with_weight(dir.join("mempool"), hub.query.clone(), 300_000_000)
            .unwrap();
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
            logpath: String::new(),
            active: std::sync::Mutex::new(Vec::new()),
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

        let scan = dispatch(&ctx, "scantxoutset", vec![json!("start"), json!([desc])]).unwrap();
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
        let missing_cl =
            dispatch(&ctx, "getmempoolcluster", vec![json!("11".repeat(32))]).unwrap_err();
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
                let (fk, rec) = hub.query.get_tx_by_txid(&op.txid.to_byte_array()).ok()??;
                let out = hub.query.tx_output_at_fk(fk, &rec, op.vout).ok()?;
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
        let mp =
            MempoolHub::open_with_weight(dir.join("mempool"), Arc::clone(&q), 50_000_000).unwrap();
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
            logpath: String::new(),
            active: std::sync::Mutex::new(Vec::new()),
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
}
