//! Bitcoin P2P: BIP324 v2 transport, headers/blocks, tip follow, tip-mode **tx relay**.

mod cache;
mod chain;
mod codec;
mod compact;
mod error;
mod ibd;
mod most_work;
mod msg_decode;
mod peer;
mod peer_dos;
mod peers;
mod seeds;
mod service;
mod tx_relay;
mod v2;

pub use cache::BlockCache;
pub use chain::{
    accept_block_header_nodos_log, headers_download_timeout_secs, headers_timeout_disconnect_log,
    headers_timeout_noban_log, ignoring_low_work_chain_log, initial_getheaders_log, log_update_tip,
    synchronizing_blockheaders_log, AcceptOutcome, ChainHub, ChainTipInfo, TipEvent,
};
pub use codec::{MAX_HEADERS_RESULTS, MAX_INV_SIZE, MAX_LOCATOR_SZ, MAX_PROTOCOL_MESSAGE_LENGTH};
pub use error::NetError;
pub use ibd::{
    format_tip_perf_sizes, ibd, ibd_cancellable, read_proc_rss, IbdConfig, ProcRss, TipPerfSizes,
    DEFAULT_BLOCKS_IN_TRANSIT_PER_PEER, DEFAULT_IBD_WINDOW,
};
pub use most_work::{
    first_best_ancestor, lca_on_best_chain, path_hashes_from_ancestor, select_most_work, sum_work,
    sum_work_for_hashes, work_better, InvalidHashSet, SelectOutcome, WorkCandidate,
};
pub use peer::{flush_tx_invs, local_service_flags};
pub use peer_dos::{
    inbound_semaphore, PeerRateLimiter, DEFAULT_MAX_BYTES_PER_SEC, DEFAULT_MAX_INBOUND,
    DEFAULT_MAX_MSGS_PER_SEC, OVERSIZE_BAN_SCORE, RATE_LIMIT_BAN_SCORE,
};
pub use peers::{
    parse_peer_addr, pick_stale_follow_evict, DialRequest, LivePeer, PeerConnType, PeerHub,
    PeerInfo, PingAction,
};
pub use rbitcoin_mempool::MempoolGraphStats;
pub use seeds::{
    default_port, dns_seed_query_host, dns_seeds, fixed_seed_hosts, pick_seed_results,
    required_seed_services, resolve_all_seeds, resolve_dns_seeds, resolve_fixed_seeds,
    seed_lookup_names, AddrMan, PeerEntry, PeerFlags,
};
pub use service::{magic_for, magic_for_params, NetConfig, P2PHandle, P2PNode};
pub use tx_relay::{
    ElectrumMempoolItem, MempoolAnnounce, MempoolHub, MempoolPerfSample, QueryUtxoProvider,
};
pub use v2::WireBytes;

/// Default number of **live download peers** during IBD (`IbdConfig::target_peers`
/// and node `--max-outbound` default).
///
/// This is **not** the seed candidate pool size. The node dials a larger sample
/// of seed addresses (typically `2 × target`, clamped) so failed connects still
/// leave enough live peers.
pub const DEFAULT_IBD_TARGET_PEERS: u32 = 16;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_defaults() {
        assert_eq!(DEFAULT_IBD_TARGET_PEERS, 16);
    }
}
