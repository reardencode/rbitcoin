//! Prometheus text exposition for `--metrics`. Each gauge is a value RPC or a
//! log line already publishes, named after that source; `phase` and `ready`
//! are `/readyz` itself.

use super::{readiness, NodeStatus, Phase};
use rbitcoin_net::ChainHub;
use std::fmt::{Display, Write};
use std::time::UNIX_EPOCH;

pub(super) const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// One scrape. Chain reads may touch the store and the mempool totals take
/// its lock, so call from the blocking pool. Cost: those chain reads
/// (`best_header_height`, tip header, `in_ibd`, scripthash lag), one peer
/// snapshot plus `byte_totals`, and one mempool fold (the same fold as
/// `getmempoolinfo`) plus the min-fee, cap, orphan, and unbroadcast reads.
pub(super) fn render(status: &NodeStatus) -> String {
    let mut out = Exposition::default();
    out.family(
        "rbitcoin_build_info",
        "gauge",
        "Version and network of this node.",
    );
    out.sample(
        "rbitcoin_build_info",
        &format!(
            "{{version=\"{}\",network=\"{}\"}}",
            env!("CARGO_PKG_VERSION"),
            status.network.as_str()
        ),
        1,
    );
    let phase = status.phase();
    out.family(
        "rbitcoin_phase",
        "gauge",
        "Bring-up phase, as /readyz names it.",
    );
    for p in Phase::ALL {
        out.sample(
            "rbitcoin_phase",
            &format!("{{phase=\"{}\"}}", p.as_str()),
            u8::from(p == phase),
        );
    }
    out.gauge(
        "rbitcoin_ready",
        "1 when /readyz answers 200.",
        u8::from(readiness(&status.ready_snapshot()).is_ok()),
    );
    out.gauge(
        "process_start_time_seconds",
        "Start time of the process since the Unix epoch in seconds.",
        status
            .started
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    );
    let rss_kb = rbitcoin_net::read_platform_rss().rss_kb;
    if rss_kb > 0 {
        out.gauge(
            "process_resident_memory_bytes",
            "Resident memory size in bytes. ibd: sizes rss= is the same reading in MiB.",
            rss_kb * 1024,
        );
    }
    if let Some(chain) = status.chain.get() {
        chain_gauges(&mut out, chain, status.sh_index);
    }
    if let Some(peers) = status.peers.get() {
        let rows = peers.snapshot();
        let (inbound, outbound) = rbitcoin_net::connection_counts(&rows);
        out.family(
            "rbitcoin_connections",
            "gauge",
            "Peer connections (getnetworkinfo.connections_in / connections_out).",
        );
        out.sample("rbitcoin_connections", "{direction=\"in\"}", inbound);
        out.sample("rbitcoin_connections", "{direction=\"out\"}", outbound);
        out.gauge(
            "rbitcoin_peer_time_offset_seconds",
            "Median outbound peer clock offset (getnetworkinfo.timeoffset).",
            rbitcoin_net::outbound_time_offset(&rows),
        );
        out.family(
            "rbitcoin_peers",
            "gauge",
            "Peer connections by network (getpeerinfo.network).",
        );
        for network in ["ipv4", "ipv6", "onion", "i2p", "cjdns"] {
            let n = rows
                .iter()
                .filter(|p| p.net.network_label() == network)
                .count();
            out.sample("rbitcoin_peers", &format!("{{network=\"{network}\"}}"), n);
        }
        let (recv, sent) = peers.byte_totals();
        out.counter(
            "rbitcoin_network_receive_bytes_total",
            "P2P bytes received (getnettotals.totalbytesrecv).",
            recv,
        );
        out.counter(
            "rbitcoin_network_transmit_bytes_total",
            "P2P bytes sent (getnettotals.totalbytessent).",
            sent,
        );
    }
    if let Some(mempool) = status.mempool.get() {
        let (size, vbytes, _fee) = mempool.live_adjusted_totals();
        out.gauge(
            "rbitcoin_mempool_transactions",
            "Mempool transactions (getmempoolinfo.size).",
            size,
        );
        out.gauge(
            "rbitcoin_mempool_bytes",
            "Sum of mempool virtual sizes (getmempoolinfo.bytes).",
            vbytes,
        );
        out.gauge(
            "rbitcoin_mempool_min_fee_sat_per_vb",
            "Minimum mempool feerate in sat/vB.",
            mempool.mempool_min_fee_sat_kvb() as f64 / 1000.0,
        );
        out.gauge(
            "rbitcoin_mempool_max_weight",
            "Mempool weight cap in weight units (getmempoolinfo.maxmempool).",
            mempool.max_weight(),
        );
        let (orphans, _orphan_wu) = mempool.orphan_stats();
        out.gauge(
            "rbitcoin_mempool_orphan_transactions",
            "Orphan transactions (getmempoolinfo.orphanage.size).",
            orphans,
        );
        out.gauge(
            "rbitcoin_mempool_unbroadcast_transactions",
            "Local transactions not yet requested (getmempoolinfo.unbroadcastcount).",
            mempool.unbroadcast_count(),
        );
        let (accepts, rejects) = mempool.accept_totals();
        out.counter(
            "rbitcoin_mempool_accepts_total",
            "Transactions the mempool accepted (tip: perf accepts=).",
            accepts,
        );
        out.counter(
            "rbitcoin_mempool_rejects_total",
            "Transactions the mempool rejected (tip: perf rejects=).",
            rejects,
        );
    }
    let (requests, us) = rbitcoin_esplora::perf_totals();
    out.counter(
        "rbitcoin_esplora_requests_total",
        "Esplora REST requests (tip: perf esplora req=).",
        requests,
    );
    out.counter(
        "rbitcoin_esplora_request_seconds_total",
        "Esplora REST handler wall time in seconds.",
        seconds(us),
    );
    let (requests, us) = rbitcoin_electrum::perf_totals();
    out.counter(
        "rbitcoin_electrum_requests_total",
        "Electrum JSON-RPC requests (tip: perf electrum req=).",
        requests,
    );
    out.counter(
        "rbitcoin_electrum_request_seconds_total",
        "Electrum dispatch wall time in seconds.",
        seconds(us),
    );
    let (blocks, bytes) = rbitcoin_net::serve_perf_totals();
    out.counter(
        "rbitcoin_block_serve_total",
        "Historical blocks served to peers (tip: perf serve n=).",
        blocks,
    );
    out.counter(
        "rbitcoin_block_serve_bytes_total",
        "Bytes of historical blocks served to peers (tip: perf serve bytes=).",
        bytes,
    );
    out.0
}

fn seconds(us: u64) -> f64 {
    us as f64 / 1e6
}

fn chain_gauges(out: &mut Exposition, chain: &ChainHub, sh_index: bool) {
    let tip = chain.query.tip_height();
    let blocks = tip.map_or(0, |h| h.0);
    out.gauge(
        "rbitcoin_blocks",
        "Active chain height (getblockchaininfo.blocks).",
        blocks,
    );
    let headers = chain.best_header_height();
    out.gauge(
        "rbitcoin_headers",
        "Best header height (getblockchaininfo.headers).",
        headers,
    );
    let progress = if headers == 0 {
        1.0
    } else {
        (f64::from(blocks) / f64::from(headers)).clamp(0.0, 1.0)
    };
    out.gauge(
        "rbitcoin_verification_progress",
        "blocks/headers (getblockchaininfo.verificationprogress).",
        progress,
    );
    let rec = tip.and_then(|h| chain.query.header_at_height(h).ok().flatten());
    let time = rec.as_ref().map_or(0, |(_, rec)| rec.timestamp);
    out.gauge(
        "rbitcoin_tip_time_seconds",
        "Tip block time (getblockchaininfo.time).",
        time,
    );
    let age = rec.as_ref().map_or(0, |(_, rec)| {
        chain
            .clock
            .now_secs()
            .saturating_sub(u64::from(rec.timestamp))
    });
    out.gauge(
        "rbitcoin_tip_age_seconds",
        "Seconds since the tip block time.",
        age,
    );
    let difficulty = rec.map_or(0.0, |(_, rec)| {
        rbitcoin_consensus::difficulty_from_bits(rec.bits)
    });
    out.gauge(
        "rbitcoin_difficulty",
        "Tip difficulty (getblockchaininfo.difficulty).",
        difficulty,
    );
    out.gauge(
        "rbitcoin_initial_block_download",
        "1 during initial block download (getblockchaininfo.initialblockdownload).",
        u8::from(chain.in_ibd()),
    );
    if sh_index {
        out.gauge(
            "rbitcoin_scripthash_lag_blocks",
            "Blocks the scripthash index trails the tip (tip: accept sh_lag=).",
            chain.query.sh_lag_heights(),
        );
    }
}

#[derive(Default)]
struct Exposition(String);

impl Exposition {
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.0, "# HELP {name} {help}\n# TYPE {name} {kind}");
    }

    fn sample(&mut self, name: &str, labels: &str, value: impl Display) {
        let _ = writeln!(self.0, "{name}{labels} {value}");
    }

    fn gauge(&mut self, name: &str, help: &str, value: impl Display) {
        self.family(name, "gauge", help);
        self.sample(name, "", value);
    }

    fn counter(&mut self, name: &str, help: &str, value: impl Display) {
        self.family(name, "counter", help);
        self.sample(name, "", value);
    }
}
