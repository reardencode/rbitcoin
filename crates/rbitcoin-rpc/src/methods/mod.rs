//! Tier-1 Core-class JSON-RPC method handlers (pure dispatch over Query/mempool).

use bitcoin::{Block, BlockHash, ScriptBuf, Transaction};
use rbitcoin_net::MempoolHub;
use rbitcoin_primitives::{
    display_hash_hex, hex_decode, hex_encode, parse_display_hash32, DisplayHashError, Network,
};
use rbitcoin_query::Query;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

pub use mine::submit_received_block;

pub(crate) fn sat_kvb_to_btc(sat_kvb: u64) -> f64 {
    sat_kvb as f64 / 100_000_000.0
}

pub(crate) fn hash_hex_display(h: &[u8; 32]) -> String {
    display_hash_hex(h)
}

/// Parse Core display-order 32-byte hex → internal byte order.
pub(crate) fn parse_hash32_display(hex: &str) -> Result<[u8; 32], Value> {
    parse_display_hash32(hex).map_err(|e| match e {
        DisplayHashError::WrongLength { .. } => {
            rpc_error(ERR_INVALID_PARAMS, "hash/txid must be 32 bytes hex")
        }
        DisplayHashError::Hex(h) => rpc_error(ERR_INVALID_PARAMS, h.to_string()),
    })
}

mod chain;
mod decode;
mod mempool;
mod mine;
mod net;

use chain::*;
use decode::*;
use mempool::*;
use mine::*;
use net::*;

/// Shared process context for RPC handlers.
pub struct RpcContext {
    pub query: Arc<Query>,
    pub mempool: Option<Arc<MempoolHub>>,
    pub network: Network,
    pub start: Instant,
    pub stop: Arc<AtomicBool>,
    /// Best-effort live peer count (updated by node; 0 if unknown).
    pub connections: Arc<AtomicU64>,
    /// Fallback IBD flag when no [`ChainHub`] is attached (tests / smoke RPC).
    /// `getblockchaininfo` prefers [`ChainHub::in_ibd`] (Core `IsInitialBlockDownload`).
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

pub(crate) fn json_u64(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_i64().and_then(|n| u64::try_from(n).ok()))
}

pub(crate) fn json_i64(v: &Value) -> Option<i64> {
    v.as_i64()
        .or_else(|| v.as_u64().and_then(|n| i64::try_from(n).ok()))
}

/// Exact BTC amount (8 decimals) so Core `Decimal` compares match sat/kvB.
pub(crate) fn json_btc_amount(sat: u64) -> Value {
    let whole = sat / 100_000_000;
    let frac = sat % 100_000_000;
    let s = format!("{whole}.{frac:08}");
    match s.parse::<serde_json::Number>() {
        Ok(n) => Value::Number(n),
        Err(_) => json!(sat as f64 / 100_000_000.0),
    }
}

/// Core `getblock` verbosity: integer, or bool (`false` → 0, `true` → 1).
pub(crate) fn opt_verbosity(params: &RpcParams, index: usize, name: &str) -> Result<u32, Value> {
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

pub(crate) fn dispatch_inner(
    ctx: &RpcContext,
    method: &str,
    params: RpcParams,
) -> Result<Value, Value> {
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
        "decoderawtransaction" => decoderawtransaction(ctx, &params),
        "decodescript" => decodescript(ctx, &params),
        "validateaddress" => validateaddress(ctx, &params),
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
        | "deriveaddresses"
        | "gettxoutsetinfo" => Err(rpc_error(
            ERR_METHOD_NOT_FOUND,
            format!("{method} is not supported (see docs/rpc.md)"),
        )),
        _ => Err(rpc_error(ERR_METHOD_NOT_FOUND, "Method not found")),
    }
}

pub(crate) fn help(params: &RpcParams) -> Result<Value, Value> {
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
pub(crate) fn echo(params: &RpcParams) -> Result<Value, Value> {
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
    "addpeeraddress",
    "getnodeaddresses",
    "getmempoolinfo",
    "getrawmempool",
    "getmempoolentry",
    "getrawtransaction",
    "decoderawtransaction",
    "decodescript",
    "validateaddress",
    "sendrawtransaction",
    "testmempoolaccept",
    "estimatesmartfee",
    "estimaterawfee",
    "generatetoaddress",
    "generatetodescriptor",
    "generateblock",
    "generate",
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
    "mockscheduler",
    "invalidateblock",
    "reconsiderblock",
    "preciousblock",
];

pub(crate) fn method_help(m: &str) -> String {
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
        "decoderawtransaction" => "decoderawtransaction hexstring (iswitness)\n\
             Decode a serialized transaction. iswitness=false refuses the BIP141 marker. \
             scriptSig asm is rust-bitcoin, not Core ScriptToAsmStr sighash suffixes."
            .into(),
        "decodescript" => "decodescript hexstring\n\
             asm, type, hex, and address when standard. No p2sh wrap, segwit wrap, \
             or descriptor inference."
            .into(),
        "validateaddress" => "validateaddress address\n\
             Happy path: isvalid, scriptPubKey, isscript, iswitness. Invalid is \
             {isvalid:false} only (no error_locations)."
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

pub(crate) fn getrpcinfo(ctx: &RpcContext) -> Value {
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
pub(crate) fn rpc_client_version(semver: &str) -> u64 {
    let mut it = semver.split('.');
    let maj: u64 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let min: u64 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let pat: u64 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    maj.saturating_mul(10_000)
        .saturating_add(min.saturating_mul(100))
        .saturating_add(pat)
}

pub(crate) fn chain_name(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "main",
        Network::Testnet => "test",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

pub(crate) fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
#[path = "../methods_tests.rs"]
mod tests;
