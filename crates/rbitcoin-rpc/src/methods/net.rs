use super::*;
use rbitcoin_net::MempoolHub;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;

pub fn getnettotals(ctx: &RpcContext) -> Value {
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

pub fn getpeerinfo(ctx: &RpcContext, hub: &rbitcoin_net::PeerHub) -> Value {
    let chain = ctx.chain.as_deref();
    let rows: Vec<Value> = hub
        .snapshot()
        .into_iter()
        .map(|p| peerinfo_json(chain, p))
        .collect();
    json!(rows)
}

#[doc(hidden)]
pub fn peer_header_height(
    chain: &rbitcoin_net::ChainHub,
    hash: &bitcoin::BlockHash,
) -> Option<i64> {
    chain.header_height(hash).map(i64::from)
}

#[doc(hidden)]
pub fn peer_block_connected(chain: &rbitcoin_net::ChainHub, hash: &bitcoin::BlockHash) -> bool {
    chain.is_connected(hash)
}

#[doc(hidden)]
pub fn outbound_median_time_offset(rows: &[rbitcoin_net::PeerInfo]) -> i64 {
    rbitcoin_net::outbound_time_offset(rows)
}

pub fn peerinfo_json(chain: Option<&rbitcoin_net::ChainHub>, p: rbitcoin_net::PeerInfo) -> Value {
    let mut recv = serde_json::Map::new();
    for (k, v) in p.bytesrecv_per_msg {
        recv.insert(k, json!(v));
    }
    let mut sent = serde_json::Map::new();
    for (k, v) in p.bytessent_per_msg {
        sent.insert(k, json!(v));
    }
    let (synced_headers, synced_blocks) = match (p.best_known, chain) {
        (Some(h), Some(chain)) => {
            let height = peer_header_height(chain, &h).unwrap_or(-1);
            let blocks = if peer_block_connected(chain, &h) {
                height
            } else {
                -1
            };
            (height, blocks)
        }
        _ => (-1, -1),
    };
    let mut row = json!({
        "id": p.id,
        "addr": p.net.to_string(),
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
        "network": p.net.network_label(),
        "synced_headers": synced_headers,
        "synced_blocks": synced_blocks,
        "timeoffset": p.time_offset_secs,
        "bip152_hb_to": p.bip152_hb_to,
        "bip152_hb_from": p.bip152_hb_from,
        "last_block": p.last_block,
        "last_transaction": p.last_transaction,
        "minfeefilter": sat_kvb_to_btc(p.minfeefilter_sat_kvb),
        "bytesrecv": p.bytesrecv,
        "bytessent": p.bytessent,
        "last_inv_sequence": p.last_inv_sequence,
        "inv_to_send": p.inv_to_send,
        "addr_processed": p.addr_processed,
        "addr_rate_limited": p.addr_rate_limited,
        "inflight": p.inflight,
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
    if let Some(asn) = p.mapped_as {
        row["mapped_as"] = json!(asn);
    }
    row
}

pub fn ping(ctx: &RpcContext) -> Result<Value, Value> {
    if let Some(hub) = ctx.peers.as_ref() {
        hub.queue_pings();
    }
    Ok(Value::Null)
}

pub fn services_names(bits: u64) -> Vec<&'static str> {
    let mut n = Vec::new();
    if bits & 1 != 0 {
        n.push("NETWORK");
    }
    if bits & 8 != 0 {
        n.push("WITNESS");
    }
    if bits & 64 != 0 {
        n.push("COMPACT_FILTERS");
    }
    if bits & 0x400 != 0 {
        n.push("NETWORK_LIMITED");
    }
    if bits & 0x800 != 0 {
        n.push("P2P_V2");
    }
    n
}

pub fn require_peers(ctx: &RpcContext) -> Result<&rbitcoin_net::PeerHub, Value> {
    ctx.peers
        .as_deref()
        .ok_or_else(|| rpc_error(ERR_MISC, "P2P session table not attached"))
}

pub fn addnode(
    ctx: &RpcContext,
    hub: &rbitcoin_net::PeerHub,
    params: &RpcParams,
) -> Result<Value, Value> {
    let node = params.req_str(0, "node")?;
    let cmd = params.req_str(1, "command")?;
    let _v2 = params.opt_bool(2, "v2transport")?;
    let ready = hub.dial_ready().map_err(|e| rpc_error(ERR_MISC, e))?;
    ready
        .addnode_host(node, cmd, ctx.network.default_p2p_port())
        .map_err(|e| rpc_error(ERR_MISC, e))?;
    Ok(Value::Null)
}

pub fn disconnectnode(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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
        let addr = rbitcoin_net::parse_peer_net(a)
            .map_err(|e| rpc_error(ERR_INVALID_PARAMS, e.to_string()))?;
        if !hub.disconnect_net(addr) {
            return Err(rpc_error(
                ERR_CLIENT_NODE_NOT_CONNECTED,
                "Node not found in connected nodes",
            ));
        }
        return Ok(Value::Null);
    }
    Err(rpc_error(ERR_INVALID_PARAMS, "address or nodeid required"))
}

pub fn addconnection(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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
pub fn addpeeraddress(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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
    // via this RPC). The node still persists addrman on shutdown / catch-up.
    let added = am
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .add_learned(addr, rbitcoin_net::MAX_ADDR_MAN);
    Ok(json!({ "success": added }))
}

/// Core `getnodeaddresses`: sample from addrman (`count=0` → all).
pub fn getnodeaddresses(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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
        let net = e.addr.network_label();
        if let Some(want) = network {
            if want != net {
                continue;
            }
        }
        out.push(json!({
            "time": now,
            "services": rbitcoin_net::local_service_flags(
                ctx.query.prune_seqsigwit(),
                ctx.peers.as_deref(),
            )
            .to_u64(),
            "address": e.addr.host_str(),
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
/// Live P2P sessions (Core `getconnectioncount`). Inbound + outbound.
/// Falls back to the outbound-follow counter when no PeerHub is attached.
pub fn connection_count(ctx: &RpcContext) -> u64 {
    if let Some(hub) = ctx.peers.as_ref() {
        hub.snapshot().len() as u64
    } else {
        ctx.connections.load(Ordering::Relaxed)
    }
}

pub fn localaddresses_json(ctx: &RpcContext) -> Value {
    let Some(hub) = ctx.peers.as_ref() else {
        return json!([]);
    };
    json!(hub
        .rpc_local_addresses()
        .into_iter()
        .map(|(address, port, score)| json!({
            "address": address,
            "port": port,
            "score": score,
        }))
        .collect::<Vec<_>>())
}

/// `getnetworkinfo.version`: Bitcoin Core 0.19.0 `CLIENT_VERSION`.
///
/// Typed clients compare this integer when they pick a response shape.
/// `bitcoincore-rpc` requires the pre-0.19 `bip9_softforks` map below
/// 190000 and then rejects our `getblockchaininfo`. This is an RPC shape
/// floor. P2P stays `protocolversion` 70016. The crate semver stays in
/// `subversion`.
pub const RPC_COMPAT_VERSION: u64 = 190_000;

pub fn getnetworkinfo(ctx: &RpcContext) -> Value {
    let (cin, cout, timeoffset) = if let Some(hub) = ctx.peers.as_ref() {
        let rows = hub.snapshot();
        let (cin, cout) = rbitcoin_net::connection_counts(&rows);
        (cin, cout, outbound_median_time_offset(&rows))
    } else {
        (0, ctx.connections.load(Ordering::Relaxed), 0)
    };
    let flags =
        rbitcoin_net::local_service_flags(ctx.query.prune_seqsigwit(), ctx.peers.as_deref());
    let svc_bits = flags.to_u64();
    json!({
        "version": RPC_COMPAT_VERSION,
        "subversion": ctx.subversion,
        "protocolversion": 70016,
        "localservices": format!("{svc_bits:016x}"),
        "localservicesnames": services_names(svc_bits),
        "localrelay": ctx.mempool.as_ref().is_none_or(|m| m.relay_enabled()),
        "timeoffset": timeoffset,
        "networkactive": true,
        "connections": cin + cout,
        "connections_in": cin,
        "connections_out": cout,
        "networks": [],
        "relayfee": MempoolHub::relay_fee_btc_per_kb(),
        "incrementalfee": MempoolHub::relay_fee_btc_per_kb(),
        "localaddresses": localaddresses_json(ctx),
        "warnings": rpc_warnings(ctx),
    })
}
