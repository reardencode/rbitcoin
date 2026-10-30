//! Tier-1 Core-class JSON-RPC method handlers (pure dispatch over Query/mempool).

use bitcoin::{Block, BlockHash, ScriptBuf, Transaction};
use rbitcoin_net::MempoolHub;
use rbitcoin_primitives::Network;
use rbitcoin_query::Query;
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

pub use chain::difficulty_rpc_f64;
pub use chain::{tip_hash_height, wait_timeout_ms};

/// Cap for `waitfor*` and `getblocktemplate` long-poll. Not a knob.
pub const RPC_WAIT_TIMEOUT_MS: u64 = 120_000;
pub use mine::{gbt_template, submit_received_block};

/// HTTP methods whose connect runs on `tip-accept` and must be awaited on the
/// request task. In-process [`dispatch`] stays synchronous.
pub fn tip_connect_method(name: &str) -> bool {
    matches!(
        name,
        "submitblock"
            | "generate"
            | "generatetoaddress"
            | "generatetodescriptor"
            | "generateblock"
            | "invalidateblock"
            | "reconsiderblock"
            | "preciousblock"
    )
}

/// Mempool admits whose script verify must be awaited on the request task.
pub fn script_admit_method(name: &str) -> bool {
    matches!(
        name,
        "sendrawtransaction" | "testmempoolaccept" | "submitpackage"
    )
}

/// HTTP methods that must not run inside `spawn_blocking`.
pub fn request_task_method(name: &str) -> bool {
    tip_connect_method(name) || script_admit_method(name)
}

/// Run `f` on `rbtc-off-pool`, holding one armed store-read permit for `f`.
/// Unscoped callers (in-process tests) take no permit.
pub async fn off_pool<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    rbitcoin_net::off_pool_budgeted(f).await
}

pub async fn dispatch_tip_connect(
    ctx: &Arc<RpcContext>,
    method: &str,
    params: RpcParams,
) -> Result<Value, Value> {
    let ctx_ref = ctx.as_ref();
    match method {
        "submitblock" => mine::submitblock_async(ctx_ref, &params).await,
        "generate" => mine::generate_async(ctx_ref, &params).await,
        "generatetoaddress" => mine::generatetoaddress_async(ctx_ref, &params).await,
        "generatetodescriptor" => mine::generatetodescriptor_async(ctx_ref, &params).await,
        "generateblock" => mine::generateblock_async(ctx_ref, &params).await,
        "invalidateblock" => chain::invalidateblock_async(ctx_ref, &params).await,
        "reconsiderblock" => chain::reconsiderblock_async(ctx_ref, &params).await,
        "preciousblock" => chain::preciousblock_async(ctx_ref, &params).await,
        "sendrawtransaction" => mempool::sendrawtransaction_async(ctx, &params).await,
        "testmempoolaccept" => mempool::testmempoolaccept_async(ctx, &params).await,
        "submitpackage" => mempool::submitpackage_async(ctx, &params).await,
        other => Err(rpc_error(ERR_METHOD_NOT_FOUND, other)),
    }
}
pub use rest::{dispatch_rest, RestReply};
thread_local! {
    static HTTP_WAIT_SATISFIED: Cell<bool> = const { Cell::new(false) };
    static HTTP_WAIT_SNAP: RefCell<Option<(String, u32)>> = const { RefCell::new(None) };
}

/// The HTTP task already waited. The blocking dispatch must not sleep again.
pub fn set_http_wait_satisfied(v: bool) {
    HTTP_WAIT_SATISFIED.with(|c| c.set(v));
}

pub fn http_wait_satisfied() -> bool {
    HTTP_WAIT_SATISFIED.with(|c| c.get())
}

/// Tip observed when this call's wait ended. Later calls in the batch must
/// not replace it.
pub fn set_http_wait_snap(v: Option<(String, u32)>) {
    HTTP_WAIT_SNAP.with(|c| *c.borrow_mut() = v);
}

pub fn take_http_wait_snap() -> Option<(String, u32)> {
    HTTP_WAIT_SNAP.with(|c| c.borrow_mut().take())
}

pub fn sat_kvb_to_btc(sat_kvb: u64) -> f64 {
    sat_kvb as f64 / 100_000_000.0
}

pub fn hash_hex_display(h: &[u8; 32]) -> String {
    rbitcoin_primitives::display_hash_hex(*h)
}

/// Parse Core display-order 32-byte hex → internal byte order.
pub fn parse_hash32_display(hex: &str) -> Result<[u8; 32], Value> {
    rbitcoin_primitives::parse_display_hash32(hex)
        .map_err(|e| rpc_error(ERR_INVALID_PARAMS, e.to_string()))
}

/// Core's `ConnectBlock` returns before adding the genesis coinbase output
/// to the coins view, and its txindex skips height 0. The coin is never
/// unspent and the tx is not an ordinary transaction.
pub fn genesis_coinbase_txid(ctx: &RpcContext) -> [u8; 32] {
    use bitcoin::hashes::Hash;
    bitcoin::blockdata::constants::genesis_block(rpc_btc_network(ctx.network)).txdata[0]
        .compute_txid()
        .to_byte_array()
}

#[doc(hidden)]
pub mod chain;
#[doc(hidden)]
pub mod decode;
mod descriptor;
#[doc(hidden)]
pub mod mempool;
#[doc(hidden)]
pub mod mine;
#[doc(hidden)]
pub mod net;
#[doc(hidden)]
pub mod rest;

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
    /// Fallback IBD flag when no `ChainHub` is attached (tests / smoke RPC).
    /// `getblockchaininfo` prefers `ChainHub::in_ibd` (relay-inhibited:
    /// `--min-chain-work` + `--max-tip-age` after densify; Core RPC name
    /// `initialblockdownload`).
    pub initial_block_download: Arc<AtomicBool>,
    /// `getnetworkinfo.subversion` (BIP14 / Core `-uacomment` shape).
    pub subversion: String,
    /// Regtest generate/submitblock. Node attaches `ChainHub` via this trait.
    pub regtest: Option<Arc<dyn RpcRegtest>>,
    /// Live P2P sessions (`getpeerinfo` / `addnode` / `disconnectnode`).
    pub peers: Option<Arc<rbitcoin_net::PeerHub>>,
    /// Live chain (invalidate / reconsider / precious).
    pub chain: Option<Arc<rbitcoin_net::ChainHub>>,
    /// Shared addrman for `addpeeraddress` / seednode (optional).
    pub addrman: Option<Arc<std::sync::Mutex<rbitcoin_net::AddrMan>>>,
    /// Core `getrpcinfo.logpath` (`{datadir}/debug.log`).
    pub logpath: String,
    /// Core `-alertnotify` (`%s` = warning). Fired once when warnings appear.
    pub alert_notify: Option<String>,
    /// Latches after the first alertnotify invocation.
    pub alert_fired: Arc<AtomicBool>,
    /// `-blocksonly`: the pool accepts local transactions and does not relay
    /// them. Mining and raw-mempool listing stay off for the life of the node.
    pub blocksonly: bool,
    /// `submitpackage` uses Core `IsChildWithParents` (the node's
    /// `RBITCOIN_RPC_PACKAGE_DIALECT`). Off by default.
    pub package_dialect: bool,
    /// In-flight RPC methods for `getrpcinfo.active_commands`.
    pub active: Arc<std::sync::Mutex<RpcActive>>,
}

/// Concurrent `dispatch` entries keyed by id (not a Vec pop).
#[derive(Default)]
pub struct RpcActive {
    pub next: u64,
    pub cmds: HashMap<u64, (String, Instant)>,
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
    /// Local store fault, not a verdict on the block.
    /// Core `state.IsError()`: `RPC_VERIFY_ERROR`, not a BIP22 result.
    Error(String),
}

/// Regtest-only mine + accept. Implemented by the node (not a mining product).
pub trait RpcRegtest: Send + Sync {
    /// `record_assembly`: each block is a pool assembly for `getmininginfo`.
    fn generate_to_script(
        &self,
        nblocks: u32,
        script_pubkey: ScriptBuf,
        extra_txs: Vec<Transaction>,
        record_assembly: bool,
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

/// [`RpcRegtest`] over the live [`rbitcoin_net::ChainHub`] confirm path.
pub struct HubRegtest(pub Arc<rbitcoin_net::ChainHub>);

impl RpcRegtest for HubRegtest {
    fn generate_to_script(
        &self,
        nblocks: u32,
        script_pubkey: ScriptBuf,
        extra_txs: Vec<Transaction>,
        record_assembly: bool,
    ) -> Result<Vec<BlockHash>, String> {
        self.0
            .generate_to_script_for_rpc(nblocks, script_pubkey, extra_txs, record_assembly)
            .map_err(|e| mine::submit_reject_reason(&e))
    }

    fn assemble_block_to_script(
        &self,
        script_pubkey: ScriptBuf,
        extra_txs: Vec<Transaction>,
    ) -> Result<Block, String> {
        self.0
            .assemble_block_to_script(script_pubkey, extra_txs)
            .map_err(|e| mine::submit_reject_reason(&e))
    }

    fn submit_block(&self, block: Block) -> SubmitBlockOutcome {
        submit_received_block(&self.0, block)
    }

    fn set_mock_time(&self, timestamp: i64) -> Result<(), String> {
        self.0.clock.set_mock(timestamp);
        Ok(())
    }
}

/// Whether `getblocktemplate`, `getrawmempool`, and pool-reading `generate`
/// may use the live pool.
pub(crate) enum PoolListing {
    /// The pool is maintained: stripped as blocks connect. Peer relay may
    /// still be off.
    Ready,
    /// Maintenance has not started, so confirmed txs may still sit in the pool.
    Downloading,
    /// `-blocksonly`. The pool is never maintained.
    Blocksonly,
}

impl RpcContext {
    pub fn uptime_secs(&self) -> u64 {
        self.start.elapsed().as_secs()
    }

    /// Blocksonly wins over catch-up so a miner does not retry forever.
    /// No pool is not catch-up: there is nothing to strip.
    pub(crate) fn pool_listing(&self) -> PoolListing {
        if self.blocksonly {
            return PoolListing::Blocksonly;
        }
        if self.mempool.as_ref().is_none_or(|m| m.pool_maintained()) {
            PoolListing::Ready
        } else {
            PoolListing::Downloading
        }
    }
}

/// An empty catch-up pool has no confirmed transactions left in it.
pub(crate) fn catch_up_pool_empty(ctx: &RpcContext) -> bool {
    ctx.mempool.as_ref().is_none_or(|m| m.live_count() == 0)
}

/// `getblocktemplate` on a catch-up pool that still holds transactions, and
/// on `-blocksonly`. An empty catch-up pool is served: regtest builds the
/// next block before the tip is recent.
pub(crate) fn refuse_unmaintained_template(ctx: &RpcContext) -> Result<(), Value> {
    match ctx.pool_listing() {
        PoolListing::Ready => Ok(()),
        PoolListing::Downloading if catch_up_pool_empty(ctx) => Ok(()),
        other => Err(pool_listing_unavailable(other)),
    }
}

pub(crate) fn pool_listing_unavailable(listing: PoolListing) -> Value {
    match listing {
        PoolListing::Blocksonly => rpc_error(
            ERR_MISC,
            "blocksonly: this node does not serve a block template",
        ),
        PoolListing::Downloading => rpc_error(
            ERR_CLIENT_IN_INITIAL_DOWNLOAD,
            "Bitcoin is downloading blocks...",
        ),
        PoolListing::Ready => rpc_error(ERR_MISC, "pool listing is available"),
    }
}

/// JSON-RPC error object (Core-ish codes).
pub fn rpc_error(code: i64, message: impl Into<String>) -> Value {
    json!({ "code": code, "message": message.into() })
}

pub const ERR_MISC: i64 = -1;
/// Core `RPC_CLIENT_IN_INITIAL_DOWNLOAD`.
pub const ERR_CLIENT_NOT_CONNECTED: i64 = -9;
pub const ERR_CLIENT_IN_INITIAL_DOWNLOAD: i64 = -10;
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
/// Core `RPC_INTERNAL_ERROR` (undo data that does not read).
pub const ERR_INTERNAL: i64 = -32603;
pub const ERR_METHOD_NOT_FOUND: i64 = -32601;

pub fn map_query(e: rbitcoin_query::QueryError, pruned: &'static str) -> Value {
    match e {
        rbitcoin_store::StoreError::Pruned { .. } => rpc_error(ERR_INVALID_PARAMETER, pruned),
        other => rpc_error(ERR_MISC, other.to_string()),
    }
}

/// JSON-RPC `params`: positional array or Core named object.
#[derive(Clone, Debug, Default)]
pub struct RpcParams {
    pub pos: Vec<Value>,
    pub named: Option<serde_json::Map<String, Value>>,
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

    pub fn named(named: serde_json::Map<String, Value>) -> Self {
        Self {
            pos: Vec::new(),
            named: Some(named),
        }
    }

    /// JSON-RPC `params`. An object key `args` holding an array is the
    /// positional list (Core mixed named calls), not a parameter name.
    pub fn from_json(v: &Value) -> Option<Self> {
        match v {
            Value::Null => Some(Self::empty()),
            Value::Array(a) => Some(Self::positional(a.clone())),
            Value::Object(m) => {
                let mut named = m.clone();
                let pos = match named.get("args") {
                    Some(Value::Array(a)) => {
                        let pos = a.clone();
                        named.remove("args");
                        pos
                    }
                    _ => Vec::new(),
                };
                Some(Self {
                    pos,
                    named: if named.is_empty() { None } else { Some(named) },
                })
            }
            _ => None,
        }
    }

    pub fn get(&self, index: usize, name: &str) -> Option<&Value> {
        if let Some(m) = &self.named {
            if let Some(v) = m.get(name) {
                return Some(v);
            }
            // Named miss falls through to positional (mixed JSON-RPC).
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

    pub fn opt_i64(&self, index: usize, name: &str) -> Result<Option<i64>, Value> {
        match self.get(index, name) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => json_i64(v)
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

pub fn json_u64(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_i64().and_then(|n| u64::try_from(n).ok()))
}

pub fn json_i64(v: &Value) -> Option<i64> {
    v.as_i64()
        .or_else(|| v.as_u64().and_then(|n| i64::try_from(n).ok()))
}

/// Core `getblock` verbosity: integer, or bool (`false` → 0, `true` → 1).
pub fn opt_verbosity(params: &RpcParams, index: usize, name: &str) -> Result<u32, Value> {
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
    let _active = ActiveCall::enter(&ctx.active, method);
    dispatch_inner(ctx, method, params.into())
}

/// One `getrpcinfo.active_commands` entry for the life of the guard.
pub struct ActiveCall<'a> {
    pub active: &'a std::sync::Mutex<RpcActive>,
    pub id: u64,
}

impl<'a> ActiveCall<'a> {
    pub fn enter(active: &'a std::sync::Mutex<RpcActive>, method: &str) -> Self {
        let id = active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .enter(method);
        Self { active, id }
    }
}

impl Drop for ActiveCall<'_> {
    fn drop(&mut self) {
        self.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .leave(self.id);
    }
}

pub fn dispatch_inner(ctx: &RpcContext, method: &str, params: RpcParams) -> Result<Value, Value> {
    match method {
        "help" => help(&params),
        "echo" | "echojson" => echo(&params),
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
            let Some(hub) = ctx.peers.as_ref() else {
                return Ok(json!([]));
            };
            Ok(getpeerinfo(ctx, hub))
        }
        "ping" => {
            params.reject_unknown(&[])?;
            ping(ctx)
        }
        "addnode" => {
            params.reject_unknown(&["node", "command", "v2transport"])?;
            let hub = require_peers(ctx)?;
            addnode(ctx, hub, &params)
        }
        "disconnectnode" => disconnectnode(ctx, &params),
        "addconnection" => addconnection(ctx, &params),
        "addpeeraddress" => addpeeraddress(ctx, &params),
        "getnodeaddresses" => getnodeaddresses(ctx, &params),
        "getmempoolinfo" => {
            params.reject_unknown(&[])?;
            getmempoolinfo(ctx)
        }
        "getrawmempool" => getrawmempool(ctx, &params),
        "getorphantxs" => getorphantxs(ctx, &params),
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
        "gettxout" => gettxout(ctx, &params),
        "getindexinfo" => getindexinfo(ctx, &params),
        "getchaintips" => getchaintips(ctx, &params),
        "getdeploymentinfo" => getdeploymentinfo(ctx, &params),
        "waitforblock" => waitforblock(ctx, &params),
        "waitforblockheight" => waitforblockheight(ctx, &params),
        "waitfornewblock" => waitfornewblock(ctx, &params),
        "getblocktemplate" => getblocktemplate(ctx, &params),
        "getmininginfo" => {
            params.reject_unknown(&[])?;
            getmininginfo(ctx)
        }
        "prioritisetransaction" => prioritisetransaction(ctx, &params),
        "getprioritisedtransactions" => getprioritisedtransactions(ctx, &params),
        "getmempoolcluster" => getmempoolcluster(ctx, &params),
        "getmempoolancestors" => getmempoolancestors(ctx, &params),
        "getmempooldescendants" => getmempooldescendants(ctx, &params),
        "getmempoolfeeratediagram" => getmempoolfeeratediagram(ctx, &params),
        "submitpackage" => submitpackage(ctx, &params),
        "gettxspendingprevout" => gettxspendingprevout(ctx, &params),
        "getblockfilter" => getblockfilter(ctx, &params),
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

pub fn help(params: &RpcParams) -> Result<Value, Value> {
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
#[doc(hidden)]
pub const ECHO_NAMES: [&str; 10] = [
    "arg0", "arg1", "arg2", "arg3", "arg4", "arg5", "arg6", "arg7", "arg8", "arg9",
];

/// Return params as a positional array (operator testing RPC).
///
/// AuthServiceProxy mixed: `{args: [0, 1], arg3: 3}` → `[0, 1, null, 3]`.
/// Named-only `arg9` sizes the array to 10 with null holes.
pub fn echo(params: &RpcParams) -> Result<Value, Value> {
    const ECHO_ALLOWED: [&str; 11] = [
        "args", "arg0", "arg1", "arg2", "arg3", "arg4", "arg5", "arg6", "arg7", "arg8", "arg9",
    ];
    params.reject_unknown(&ECHO_ALLOWED)?;

    let mut pos = params.pos.clone();
    if let Some(m) = &params.named {
        if let Some(v) = m.get("args") {
            let arr = v.as_array().ok_or_else(|| {
                rpc_error(
                    ERR_TYPE_ERROR,
                    format!(
                        "JSON value of type {} is not of expected type array",
                        json_type_name(v)
                    ),
                )
            })?;
            pos = arr.clone();
        }
        for (i, name) in ECHO_NAMES.iter().enumerate() {
            if m.contains_key(*name) && i < pos.len() {
                return Err(rpc_error(
                    ERR_INVALID_PARAMETER,
                    format!(
                        "Parameter {name} specified twice both as positional and named argument"
                    ),
                ));
            }
        }
    }

    let mut max_idx: Option<usize> = if pos.is_empty() {
        None
    } else {
        Some(pos.len() - 1)
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
    for (i, v) in pos.iter().enumerate() {
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

#[doc(hidden)]
pub const METHOD_LIST: &[&str] = &[
    "help",
    "echo",
    "echojson",
    "getrpcinfo",
    "uptime",
    "stop",
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
    "getblockfilter",
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

#[doc(hidden)]
pub const NAMED_HELP: &[(&str, &str)] = &[
    (
        "estimatesmartfee",
        "estimatesmartfee conf_target (estimate_mode options)\n\
         Returns this node's 10-minute inclusion frontier feerate (BTC/kvB), \
         not Core historical multi-horizon. `options.fee_rate_estimator` and \
         `options.verbosity` are checked and do not change the feerate. \
         See docs/mempool-fee-estimation.md.",
    ),
    (
        "estimaterawfee",
        "estimaterawfee conf_target (threshold)\n\
         Regtest/harness surface matching Core's RPC name. Returns this node's \
         10-minute inclusion frontier (same product as estimatesmartfee).",
    ),
    (
        "getblockchaininfo",
        "getblockchaininfo\nReturns tip height, chain name, and IBD flag.\n\
         initialblockdownload is relay-inhibited after densify (min-chain-work +\n\
         max-tip-age), not still catching up. chainwork is summed header work\n\
         (regtest 2/block). size_on_disk is a walk of store file lengths (plus\n\
         the cold store when split). verificationprogress is blocks/headers (1.0 when\n\
         headers is 0).",
    ),
    (
        "getblockstats",
        "getblockstats hash_or_height ( stats )\n\
         Fee / UTXO / weight statistics from stamped txstat rows (reconstruct fallback).",
    ),
    (
        "generatetoaddress",
        "generatetoaddress nblocks address (maxtries)\n\
         Regtest harness only. Mines nblocks paying address via the P2P accept path.",
    ),
    (
        "generateblock",
        "generateblock output transactions (submit)\n\
         Regtest harness only. One block paying output (address or hex script). \
         submit=false returns {hash,hex} without connecting the block.",
    ),
    (
        "generate",
        "generate\n\nhas been replaced by the -generate cli option. Refer to -help for more information.\n",
    ),
    (
        "mockscheduler",
        "mockscheduler delta_seconds\n\
         Regtest harness only. Advance the scheduler; rebroadcast unbroadcast txs.",
    ),
    (
        "generatetodescriptor",
        "generatetodescriptor nblocks descriptor (maxtries)\n\
         Regtest harness only. raw(HEX), addr(ADDRESS), or a bare address.",
    ),
    (
        "getblockfilter",
        "getblockfilter blockhash (filtertype)\n\
         BIP158 basic filter when --block-filter-index has reached the tip.",
    ),
    (
        "decoderawtransaction",
        "decoderawtransaction hexstring (iswitness)\n\
         Decode a serialized transaction. iswitness=false refuses the BIP141 marker. \
         scriptSig asm is rust-bitcoin, not Core ScriptToAsmStr sighash suffixes.",
    ),
    (
        "decodescript",
        "decodescript hexstring\n\
         asm, type, hex, address when standard, and desc. No p2sh wrap, \
         segwit wrap, or miniscript.",
    ),
    (
        "validateaddress",
        "validateaddress address\n\
         Happy path: isvalid, scriptPubKey, isscript, iswitness. Invalid is \
         {isvalid:false} only (no error_locations).",
    ),
    (
        "gettxout",
        "gettxout txid n (include_mempool)\n\
         Connected Class A + mempool. Default include_mempool hides an out spent by a live mempool tx, confirmed or not.",
    ),
    (
        "sendrawtransaction",
        "sendrawtransaction hexstring (maxfeerate) (maxburnamount)\n\
         RPC submit only. Default maxfeerate 0.10 BTC/kvB (0 unlimited; >=1 BTC/kvB is a parameter error). \
         A pre-0.19 boolean allowhighfees there: true is unlimited, false the default. \
         Default maxburnamount 0. P2P relay is not capped.",
    ),
    (
        "getchaintips",
        "getchaintips — active + held/archive side tips + headers-only.",
    ),
    (
        "getdeploymentinfo",
        "getdeploymentinfo (blockhash)\nBuried deployments from ChainParams. No BIP9.",
    ),
    (
        "getblocktemplate",
        "getblocktemplate (template_request)\n\
         All networks. Template from select_block_template; proposal validates \
         without connecting. rules must include segwit (and signet on signet). \
         longpollid waits for a new tip or mempool/priority change. version \
         follows the regtest testdummy deployment (bit 28).",
    ),
    (
        "getmininginfo",
        "getmininginfo\nTip height and hash, difficulty, next block bits, pooledtx, blockmintxfee (BTC/kvB). All networks.",
    ),
    (
        "getnetworkhashps",
        "getnetworkhashps (nblocks) (height)\n\
         Estimated hashes per second from chainwork delta over the lookup \
         window (min/max header time). nblocks<=0 uses the difficulty \
         retarget length. See docs/rpc.md.",
    ),
    (
        "prioritisetransaction",
        "prioritisetransaction txid dummy fee_delta\nLocal mining fee delta (sat). dummy must be 0.",
    ),
    (
        "getprioritisedtransactions",
        "getprioritisedtransactions\nMap of txid → fee_delta / in_mempool / modified_fee.",
    ),
    (
        "submitblock",
        "submitblock hexdata (dummy)\n\
         All networks. Same receive path as a P2P block.",
    ),
    (
        "submitheader",
        "submitheader hexdata\n\
         All networks. Persist a header via the P2P header path (`ensure_header`).",
    ),
    (
        "getpeerinfo",
        "getpeerinfo\n\
         Returns data about each connected network node as a json array of objects.\n\
         Valid networks: (ipv4, ipv6, onion, i2p, cjdns, not_publicly_routable)",
    ),
    (
        "getorphantxs",
        "getorphantxs ( verbosity )\n\
         Shows transactions in the tx orphanage.\n\
         EXPERIMENTAL warning: this call may be changed in future releases.",
    ),
    (
        "help",
        "help\nhelp ( \"command\" ) — list methods or describe one.",
    ),
    (
        "echo",
        "echo\necho ( arg0 ... arg9 ) — return arguments as a positional array.",
    ),
    (
        "echojson",
        "echojson\nechojson ( arg0 ... arg9 ) — return arguments as a positional array.",
    ),
];

pub fn method_help(m: &str) -> String {
    for (name, text) in NAMED_HELP {
        if *name == m {
            return (*text).into();
        }
    }
    if METHOD_LIST.contains(&m) {
        format!("{m} — see docs/rpc.md")
    } else {
        format!("unknown method {m}")
    }
}

pub fn getrpcinfo(ctx: &RpcContext) -> Value {
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

pub fn chain_name(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "main",
        Network::Testnet => "test",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

pub fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
