use super::*;
use rbitcoin_net::MempoolHub;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;

pub(crate) fn getnettotals(ctx: &RpcContext) -> Value {
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

pub(crate) fn getpeerinfo(ctx: &RpcContext) -> Value {
    let Some(hub) = ctx.peers.as_ref() else {
        return json!([]);
    };
    let rows: Vec<Value> = hub.snapshot().into_iter().map(peerinfo_json).collect();
    json!(rows)
}

pub(crate) fn peerinfo_json(p: rbitcoin_net::PeerInfo) -> Value {
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
        "bytesrecv": p.bytesrecv,
        "bytessent": p.bytessent,
        "last_inv_sequence": p.last_inv_sequence,
        "inv_to_send": p.inv_to_send,
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

pub(crate) fn ping(ctx: &RpcContext) -> Result<Value, Value> {
    if let Some(hub) = ctx.peers.as_ref() {
        hub.queue_pings();
    }
    Ok(Value::Null)
}

pub(crate) fn services_names(bits: u64) -> Vec<&'static str> {
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

pub(crate) fn require_peers(ctx: &RpcContext) -> Result<&rbitcoin_net::PeerHub, Value> {
    ctx.peers
        .as_deref()
        .ok_or_else(|| rpc_error(ERR_MISC, "P2P session table not attached"))
}

pub(crate) fn addnode(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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

pub(crate) fn disconnectnode(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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

pub(crate) fn addconnection(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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
pub(crate) fn addpeeraddress(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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
pub(crate) fn getnodeaddresses(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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
/// Live P2P sessions (Core `getconnectioncount`). Inbound + outbound.
/// Falls back to the outbound-follow counter when no PeerHub is attached.
pub(crate) fn connection_count(ctx: &RpcContext) -> u64 {
    if let Some(hub) = ctx.peers.as_ref() {
        hub.snapshot().len() as u64
    } else {
        ctx.connections.load(Ordering::Relaxed)
    }
}

pub(crate) fn localaddresses_json(ctx: &RpcContext) -> Value {
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

pub(crate) fn getnetworkinfo(ctx: &RpcContext) -> Value {
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
        "localaddresses": localaddresses_json(ctx),
        "warnings": rpc_warnings(ctx),
    })
}
