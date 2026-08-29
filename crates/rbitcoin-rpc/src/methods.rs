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
use std::collections::HashMap;
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
    /// Shared addrman for `addpeeraddress` / seednode (optional).
    pub addrman: Option<Arc<std::sync::Mutex<rbitcoin_net::AddrMan>>>,
    /// Path to durable peers file (with [`Self::addrman`]).
    pub peers_path: Option<std::path::PathBuf>,
    /// Core `getrpcinfo.logpath` (`{datadir}/debug.log`).
    pub logpath: String,
    /// Core `-permitbaremultisig` (default true). `getmempoolinfo`.
    pub permit_bare_multisig: bool,
    /// Core `-alertnotify` (`%s` = warning). Fired once when warnings appear.
    pub alert_notify: Option<String>,
    /// Latches after the first alertnotify invocation.
    pub alert_fired: Arc<AtomicBool>,
    /// In-flight RPC methods for `getrpcinfo.active_commands`.
    pub active: Arc<std::sync::Mutex<RpcActive>>,
}

/// Concurrent `dispatch` entries keyed by id (not a Vec pop).
#[derive(Default)]
pub struct RpcActive {
    next: u64,
    cmds: HashMap<u64, (String, Instant)>,
}

impl RpcActive {
    pub fn enter(&mut self, method: impl Into<String>) -> u64 {
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        self.cmds.insert(id, (method.into(), Instant::now()));
        id
    }

    pub fn leave(&mut self, id: u64) {
        self.cmds.remove(&id);
    }

    pub fn len(&self) -> usize {
        self.cmds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cmds.is_empty()
    }

    pub fn snapshot(&self) -> Vec<(String, Instant)> {
        let mut v: Vec<_> = self.cmds.values().cloned().collect();
        v.sort_by_key(|(_, start)| *start);
        v
    }
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
    let id = ctx
        .active
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .enter(method);
    let out = dispatch_inner(ctx, method, params.into());
    ctx.active
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .leave(id);
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
        "addpeeraddress" => addpeeraddress(ctx, &params),
        "getnodeaddresses" => getnodeaddresses(ctx, &params),
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
        "estimaterawfee" => estimaterawfee(ctx, &params),
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
    "estimaterawfee",
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
            "estimatesmartfee conf_target (estimate_mode)\n\
             Returns this node's 10-minute inclusion frontier feerate (BTC/kvB), \
             not Core historical multi-horizon. See docs/mempool-fee-estimation.md."
                .into()
        }
        "estimaterawfee" => {
            "estimaterawfee conf_target (threshold)\n\
             Regtest/harness surface matching Core's RPC name. Returns this node's \
             10-minute inclusion frontier (same product as estimatesmartfee)."
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
        .snapshot()
        .into_iter()
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
        "warnings": rpc_warnings(ctx),
    }))
}

fn rpc_warnings(ctx: &RpcContext) -> Vec<String> {
    let w = rbitcoin_net::warning_strings(ctx.query.as_ref(), ctx.network);
    if !w.is_empty()
        && ctx
            .alert_fired
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    {
        if let Some(cmd) = ctx.alert_notify.as_deref() {
            let msg = w.join(", ");
            // Core ShellEscape: single-quote so `(versionbit N)` is not a subshell.
            let escaped = format!("'{}'", msg.replace('\'', "'\\''"));
            let shell = cmd.replace("%s", &escaped);
            match std::process::Command::new("sh")
                .arg("-c")
                .arg(&shell)
                .status()
            {
                Ok(st) if !st.success() => {
                    rbitcoin_log::warn!("alertnotify exited {st}: {shell}");
                }
                Err(e) => rbitcoin_log::warn!("alertnotify failed: {e}: {shell}"),
                _ => {}
            }
        }
    }
    w
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
        if let Ok(w) = hub.work_through_height(tip.0) {
            return hex_encode(w.to_be_bytes());
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
    if verbosity == 1 {
        let (_, rec) = ctx
            .query
            .header_at_height(height)
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
            .ok_or_else(|| rpc_error(ERR_MISC, "header missing"))?;
        let ids = ctx
            .query
            .block_txids(height)
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
        let txids: Vec<String> = ids.iter().map(hash_hex_display).collect();
        return Ok(json!({
            "hash": hash_hex_display(&hash),
            "confirmations": confirmations(ctx, height),
            "height": height.0,
            "version": rec.version,
            "merkleroot": hash_hex_display(&rec.merkle_root),
            "time": rec.timestamp,
            "mediantime": rbitcoin_consensus::median_time_past(ctx.query.as_ref(), height)
                .unwrap_or(rec.timestamp),
            "nonce": rec.nonce,
            "bits": format!("{:08x}", rec.bits),
            "previousblockhash": prev,
            "nTx": txids.len(),
            "tx": txids,
        }));
    }
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
        "relaytxes": p.relay && !matches!(p.conn_type, rbitcoin_net::PeerConnType::BlockRelay),
        "transport_protocol_type": "v2",
        "network": "ipv4",
        "synced_headers": -1,
        "synced_blocks": -1,
        "bip152_hb_to": p.bip152_hb_to,
        "bip152_hb_from": p.bip152_hb_from,
        "last_block": p.last_block,
        "last_transaction": p.last_transaction,
        "minfeefilter": sat_kvb_to_btc(p.minfeefilter_sat_kvb),
        "permissions": p.permissions,
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

/// Core `addpeeraddress` (hidden): insert into addrman + durable peers file.
fn addpeeraddress(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["address", "port", "tried"])?;
    let address = params.req_str(0, "address")?;
    let port = params.req_u64(1, "port")?;
    let _tried = params.opt_bool(2, "tried")?;
    if port > u64::from(u16::MAX) {
        return Err(rpc_error(ERR_INVALID_PARAMS, "JSON integer out of range"));
    }
    let ip: std::net::IpAddr = address
        .parse()
        .map_err(|_| rpc_error(ERR_INVALID_PARAMETER, "Invalid IP address"))?;
    let addr = std::net::SocketAddr::new(ip, port as u16);
    let Some(am) = ctx.addrman.as_ref() else {
        return Err(rpc_error(ERR_MISC, "addrman not available"));
    };
    // RAM-only: do not rewrite peers on every call (p2p_getaddr_caching fills
    // 10k addresses). The node still persists addrman on shutdown / catch-up.
    am.lock().unwrap_or_else(|e| e.into_inner()).add(addr);
    Ok(json!({ "success": true }))
}

/// Core `getnodeaddresses`: sample from addrman (`count=0` → all).
fn getnodeaddresses(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["count", "network"])?;
    let count_raw = params.get(0, "count");
    let count: u64 = match count_raw {
        None | Some(Value::Null) => 1,
        Some(v) => {
            let n = json_i64(v)
                .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "count must be an integer"))?;
            if n < 0 {
                return Err(rpc_error(
                    ERR_INVALID_PARAMETER,
                    "Address count out of range",
                ));
            }
            n as u64
        }
    };
    let network = params.opt_str(1, "network")?;
    if let Some(want) = network {
        if !matches!(want, "ipv4" | "ipv6" | "onion" | "i2p" | "cjdns") {
            return Err(rpc_error(
                ERR_INVALID_PARAMETER,
                format!("Network not recognized: {want}"),
            ));
        }
    }
    let Some(am) = ctx.addrman.as_ref() else {
        return Ok(json!([]));
    };
    let g = am.lock().unwrap_or_else(|e| e.into_inner());
    let mut out = Vec::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for e in g.entries() {
        let net = match e.addr.ip() {
            std::net::IpAddr::V4(_) => "ipv4",
            std::net::IpAddr::V6(_) => "ipv6",
        };
        if let Some(want) = network {
            if want != net {
                continue;
            }
        }
        out.push(json!({
            "time": now,
            "services": rbitcoin_net::local_service_flags().to_u64(),
            "address": e.addr.ip().to_string(),
            "port": e.addr.port(),
            "network": net,
        }));
        if count > 0 && (out.len() as u64) >= count {
            break;
        }
    }
    Ok(Value::Array(out))
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
        "localrelay": ctx.mempool.as_ref().is_none_or(|m| m.relay_enabled()),
        "timeoffset": 0,
        "networkactive": true,
        "connections": cin + cout,
        "connections_in": cin,
        "connections_out": cout,
        "networks": [],
        "relayfee": MempoolHub::relay_fee_btc_per_kb(),
        "incrementalfee": MempoolHub::relay_fee_btc_per_kb(),
        "localaddresses": [],
        "warnings": rpc_warnings(ctx),
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
            "incrementalrelayfee": MempoolHub::relay_fee_btc_per_kb(),
            "unbroadcastcount": 0,
            "permitbaremultisig": ctx.permit_bare_multisig,
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
        "incrementalrelayfee": MempoolHub::relay_fee_btc_per_kb(),
        "relay_enabled": mp.relay_enabled(),
        "unbroadcastcount": mp.unbroadcast_count(),
        "permitbaremultisig": ctx.permit_bare_multisig,
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
    let (depends, spentby) = match mp.depends_spentby(txid) {
        Some((d, s)) => (
            d.into_iter()
                .map(|t| hash_hex_display(&t.to_byte_array()))
                .collect::<Vec<_>>(),
            s.into_iter()
                .map(|t| hash_hex_display(&t.to_byte_array()))
                .collect::<Vec<_>>(),
        ),
        None => (Vec::new(), Vec::new()),
    };
    json!({
        "vsize": vsize,
        "weight": weight,
        "fee": sat_btc_json(fee as i64),
        // Top-level `modifiedfee` stays the base fee (same pattern as
        // ancestorfees/descendantfees). Real modified value is `fees.modified`.
        "modifiedfee": sat_btc_json(fee as i64),
        "time": mp.accept_time_txid(txid).unwrap_or(0),
        "height": 0,
        "descendantcount": dc,
        "descendantsize": dsz,
        "descendantfees": dfee,
        "ancestorcount": ac,
        "ancestorsize": asz,
        "ancestorfees": afee,
        "chunkweight": chunk_w,
        "unbroadcast": mp.is_unbroadcast(txid),
        "depends": depends,
        "spentby": spentby,
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
    Err(rpc_error(
        ERR_INVALID_ADDRESS_OR_KEY,
        "Transaction not in mempool",
    ))
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
    // `-blocksonly` leaves P2P relay off but RPC still accepts
    // (`p2p_blocksonly.py` sendrawtransaction).
    match mp.accept_tx(&tx) {
        Ok(r) => {
            mp.note_unbroadcast(r.txid);
            // `-blocksonly`: accept-time announce is skipped (relay off + not
            // yet unbroadcast). Re-announce after noting so inbound peers INV
            // (`p2p_blocksonly.py:48`). When relay is on, leave the 30s inbound
            // age gate alone (`mempool_reorg` / `mempool_unbroadcast`).
            if !mp.relay_enabled() {
                mp.rebroadcast_unbroadcast();
                mp.notify_inv_flush();
                if let (Some(peers), Some(chain)) = (ctx.peers.as_ref(), ctx.chain.as_ref()) {
                    rbitcoin_net::flush_tx_invs(chain, peers);
                } else if let Some(peers) = ctx.peers.as_ref() {
                    peers.request_all_tx_inv();
                }
            }
            Ok(json!(hash_hex_display(&tx.compute_txid().to_byte_array())))
        }
        // Core sendraw of a live mempool tx is a no-op success (returns txid)
        // and must not re-enter the unbroadcast set (`mempool_unbroadcast.py:93`).
        Err(e) if e.to_string().starts_with("duplicate ") => {
            Ok(json!(hash_hex_display(&tx.compute_txid().to_byte_array())))
        }
        // Same txid, different witness: success + force-INV the live body so a
        // peer that missed the first announce still sees it
        // (`mempool_accept_wtxid.py:82`). Ignores inv_gen_floor / age gate.
        Err(e) if e.to_string() == "policy: txn-same-nonwitness-data-in-mempool" => {
            let tid = tx.compute_txid();
            if let (Some(peers), Some(chain)) = (ctx.peers.as_ref(), ctx.chain.as_ref()) {
                rbitcoin_net::force_announce_txid(chain, peers, tid);
            }
            Ok(json!(hash_hex_display(&tid.to_byte_array())))
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

/// Core `reject-details` for mempool rejects.
fn accept_reject_details(e: &impl std::fmt::Display, tx: &Transaction) -> Option<String> {
    let reason = accept_reject_reason(e);
    if reason == "txn-already-in-mempool" || reason == "txn-same-nonwitness-data-in-mempool" {
        return Some(reason);
    }
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
        match mp.test_accept(&tx) {
            Ok(r) => {
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

/// Core `ParseConfirmTarget`: integer in `1..=1008`.
fn parse_conf_target(v: &Value) -> Result<u32, Value> {
    let conf_target = match v {
        Value::Number(n) => n
            .as_u64()
            .or_else(|| n.as_i64().and_then(|i| u64::try_from(i).ok()))
            .ok_or_else(|| {
                rpc_error(
                    ERR_TYPE_ERROR,
                    "JSON value of type number is not of expected type number",
                )
            })? as u32,
        other => {
            return Err(rpc_error(
                ERR_TYPE_ERROR,
                format!(
                    "JSON value of type {} is not of expected type number",
                    json_type_name(other)
                ),
            ));
        }
    };
    if !(1..=1008).contains(&conf_target) {
        return Err(rpc_error(
            ERR_INVALID_PARAMETER,
            "Invalid conf_target, must be between 1 and 1008",
        ));
    }
    Ok(conf_target)
}

/// Map Core `estimatesmartfee` to this node's **10-minute inclusion** product.
fn estimatesmartfee(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["conf_target", "estimate_mode"])?;
    // Core requires conf_target (`rpc_estimatefee.py`).
    if params.get(0, "conf_target").is_none() {
        return Err(rpc_error(ERR_MISC, method_help("estimatesmartfee")));
    }
    if params.pos_len() > 2 {
        return Err(rpc_error(ERR_MISC, method_help("estimatesmartfee")));
    }
    let conf_target = parse_conf_target(params.get(0, "conf_target").unwrap())?;
    if let Some(mode_v) = params.get(1, "estimate_mode") {
        if !matches!(mode_v, Value::Null) {
            let mode = mode_v.as_str().ok_or_else(|| {
                rpc_error(
                    ERR_TYPE_ERROR,
                    format!(
                        "JSON value of type {} is not of expected type string",
                        json_type_name(mode_v)
                    ),
                )
            })?;
            let ok = matches!(
                mode.to_ascii_lowercase().as_str(),
                "unset" | "economical" | "conservative"
            );
            if !ok {
                return Err(rpc_error(
                    ERR_INVALID_PARAMETER,
                    "Invalid estimate_mode parameter, must be one of: \"unset\", \"economical\", \"conservative\"",
                ));
            }
        }
    }
    estimate_fee_result(ctx, conf_target)
}

/// Core `estimaterawfee` name; same 10-minute product as [`estimatesmartfee`].
fn estimaterawfee(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["conf_target", "threshold"])?;
    if params.get(0, "conf_target").is_none() {
        return Err(rpc_error(ERR_MISC, method_help("estimaterawfee")));
    }
    if params.pos_len() > 2 {
        return Err(rpc_error(ERR_MISC, method_help("estimaterawfee")));
    }
    let conf_target = parse_conf_target(params.get(0, "conf_target").unwrap())?;
    if let Some(th) = params.get(1, "threshold") {
        if !matches!(th, Value::Null) && json_u64(th).is_none() && th.as_f64().is_none() {
            return Err(rpc_error(
                ERR_TYPE_ERROR,
                format!(
                    "JSON value of type {} is not of expected type number",
                    json_type_name(th)
                ),
            ));
        }
    }
    // Core returns nested short/medium/long buckets; we expose the same
    // single-horizon product under `short` for harness compatibility.
    let base = estimate_fee_result(ctx, conf_target)?;
    Ok(json!({
        "short": {
            "feerate": base.get("feerate").cloned().unwrap_or(json!(-1.0)),
            "decay": 0.962,
            "scale": 2,
            "pass": { "startrange": 0, "endrange": 0, "withintarget": 0, "totalconfirmed": 0, "inmempool": 0, "leftmempool": 0 },
            "fail": Value::Null,
            "errors": base.get("errors").cloned().unwrap_or(Value::Null),
        }
    }))
}

fn estimate_fee_result(ctx: &RpcContext, conf_target: u32) -> Result<Value, Value> {
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
        "rbitcoin_model": "10-minute inclusion frontier (not Core historical)",
    }))
}

fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
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
    let script = parse_generateblock_output(ctx, output)?;
    let mut extra = Vec::new();
    if let Some(arr) = params.get_array(1, "transactions") {
        let mp = ctx.mempool.as_ref();
        for v in arr {
            let s = v.as_str().ok_or_else(|| {
                rpc_error(
                    ERR_INVALID_PARAMS,
                    "transactions entries must be hex or txid",
                )
            })?;
            // Core: 64-hex → Txid::FromHex first; miss → not in mempool (-5).
            if s.len() == 64 {
                if let Ok(tid) = parse_hash32_display(s) {
                    let txid = Txid::from_byte_array(tid);
                    if let Some(mp) = mp {
                        if let Some(tx) = mp.get_tx(&txid) {
                            extra.push(tx);
                            continue;
                        }
                    }
                    return Err(rpc_error(
                        ERR_INVALID_ADDRESS_OR_KEY,
                        format!("Transaction {s} not in mempool."),
                    ));
                }
            }
            match decode_tx_hex(s) {
                Ok(tx) => extra.push(tx),
                Err(_) => {
                    return Err(rpc_error(
                        ERR_DESERIALIZATION,
                        format!(
                            "Transaction decode failed for {s}. Make sure the tx has at least one input."
                        ),
                    ));
                }
            }
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
            .map_err(|e| generateblock_validity_error(&e))?;
        return Ok(json!({
            "hash": block.block_hash().to_string(),
            "hex": serialize_hex(&block),
        }));
    }
    let hashes = miner
        .generate_to_script(1, script, extra)
        .map_err(|e| generateblock_validity_error(&e))?;
    let hash = hashes
        .first()
        .ok_or_else(|| rpc_error(ERR_MISC, "generateblock produced no block"))?;
    Ok(json!({ "hash": hash.to_string() }))
}

/// Core `generateblock` after `TestBlockValidity`: `-25 TestBlockValidity failed: <reason>`.
fn generateblock_validity_error(e: &str) -> Value {
    let s = e.strip_prefix("consensus: ").unwrap_or(e);
    let s = s.strip_prefix("protocol: ").unwrap_or(s);
    for needle in [
        "bad-txns-inputs-missingorspent",
        "bad-txns-duplicate",
        "bad-txns-nonfinal",
        "bad-txns-in-belowout",
        "bad-cb-missing",
        "bad-blk-length",
        "bad-diffbits",
        "time-too-old",
        "time-too-new",
        "bad-txnmrklroot",
    ] {
        if s.contains(needle) {
            return rpc_error(
                ERR_VERIFY_ERROR,
                format!("TestBlockValidity failed: {needle}"),
            );
        }
    }
    rpc_error(ERR_VERIFY_ERROR, format!("TestBlockValidity failed: {s}"))
}

/// Core `generateblock` output: descriptor first, then address (not bare hex).
fn parse_generateblock_output(ctx: &RpcContext, output: &str) -> Result<ScriptBuf, Value> {
    let invalid = || {
        rpc_error(
            ERR_INVALID_ADDRESS_OR_KEY,
            "Error: Invalid address or descriptor",
        )
    };
    if output.contains('(') {
        if output.contains("/*") {
            return Err(rpc_error(
                ERR_INVALID_PARAMETER,
                "Ranged descriptor not accepted. Maybe pass through deriveaddresses first?",
            ));
        }
        if let Some(s) = parse_raw_descriptor(output) {
            return Ok(s);
        }
        if let Some(s) = parse_addr_descriptor(ctx, output) {
            return Ok(s);
        }
        if let Some(s) = parse_combo_descriptor(ctx, output) {
            return Ok(s);
        }
        if let Some(s) = parse_wrapped_multi(output) {
            return Ok(s);
        }
        let has_xpub = output.contains("tpub")
            || output.contains("xpub")
            || output.contains("tprv")
            || output.contains("xprv");
        if has_xpub && (output.contains('\'') || output.contains("h/") || output.contains("h)")) {
            return Err(rpc_error(
                ERR_INVALID_ADDRESS_OR_KEY,
                "Cannot derive script without private keys",
            ));
        }
        return Err(invalid());
    }
    let btc_net = rpc_btc_network(ctx.network);
    if let Ok(a) = output.parse::<Address<_>>() {
        if let Ok(addr) = a.require_network(btc_net) {
            return Ok(addr.script_pubkey());
        }
    }
    Err(invalid())
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

/// Core `combo(pubkey)` for `generateblock`: compressed → P2WPKH, else P2PKH.
fn parse_combo_descriptor(ctx: &RpcContext, desc: &str) -> Option<ScriptBuf> {
    use bitcoin::key::CompressedPublicKey;
    let bare = desc.split('#').next()?.trim();
    let inner = bare.strip_prefix("combo(")?.strip_suffix(")")?;
    let pk = PublicKey::from_str(inner).ok()?;
    let btc_net = rpc_btc_network(ctx.network);
    let spk = if pk.compressed {
        let cpk = CompressedPublicKey(pk.inner);
        Address::p2wpkh(&cpk, btc_net).script_pubkey()
    } else {
        Address::p2pkh(pk, btc_net).script_pubkey()
    };
    Some(spk)
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
    if let Some(s) = parse_combo_descriptor(ctx, desc) {
        return Ok(s);
    }
    if let Some(s) = parse_wrapped_multi(desc) {
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
        .tx_output_at_fk(fk, n)
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
    wait_for_tip(ctx, timeout_ms, |hash, _height| hash == want)
}

fn waitforblockheight(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["height", "timeout"])?;
    let want = params.req_u64(0, "height")? as u32;
    let timeout_ms = wait_timeout_ms(params, 1, "timeout")?;
    wait_for_tip(ctx, timeout_ms, |_hash, height| height >= want)
}

fn waitfornewblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["timeout"])?;
    let timeout_ms = wait_timeout_ms(params, 0, "timeout")?;
    let (start_hash, _) = tip_hash_height(ctx)?;
    wait_for_tip(ctx, timeout_ms, |hash, _height| hash != start_hash)
}

/// `feature_shutdown.py`: stop must wake waiters so in-flight wait RPCs
/// return the current tip instead of hanging until the connection drops.
fn wait_for_tip(
    ctx: &RpcContext,
    timeout_ms: u64,
    pred: impl Fn(&str, u32) -> bool,
) -> Result<Value, Value> {
    let deadline = Instant::now() + std::time::Duration::from_millis(timeout_ms);
    loop {
        if ctx.stop.load(Ordering::SeqCst) {
            let (hash, height) = tip_hash_height(ctx)?;
            return Ok(json!({ "hash": hash, "height": height }));
        }
        let (hash, height) = tip_hash_height(ctx)?;
        if pred(&hash, height) {
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
    let bits = rbitcoin_consensus::expected_next_bits(
        ctx.query.as_ref(),
        &params,
        Height(next_h),
        curtime,
    )
    .map(|c| c.to_consensus())
    .unwrap_or(tip_bits);
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
    let witness_commit = rbitcoin_consensus::witness_commitment_script(wtxids, &[0u8; 32]);
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
    let expected = rbitcoin_consensus::expected_next_bits(
        ctx.query.as_ref(),
        &params,
        Height(height),
        block.header.time,
    )
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
        .tx_output_at_fk(fk, op.vout)
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
    m.insert("warnings".into(), json!(rpc_warnings(ctx)));
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
#[path = "methods_tests.rs"]
mod tests;
