//! Bitcoin P2P: BIP324 v2 transport, headers/blocks, tip follow, tip-mode **tx relay**.

#[doc(hidden)]
pub mod asmap;
#[doc(hidden)]
pub mod cache;
#[doc(hidden)]
pub mod chain;
#[doc(hidden)]
pub mod codec;
#[doc(hidden)]
pub mod compact;
#[doc(hidden)]
pub mod ephemeral;
#[doc(hidden)]
pub mod error;
#[doc(hidden)]
pub mod eviction;
#[doc(hidden)]
pub mod fee_history;
#[doc(hidden)]
pub mod fee_history_file;
#[doc(hidden)]
pub mod i2p_sam;
#[doc(hidden)]
pub mod most_work;
#[doc(hidden)]
pub mod msg_decode;
#[doc(hidden)]
pub mod net_permissions;
#[doc(hidden)]
pub mod netaddr;
#[doc(hidden)]
pub mod netgroup;
#[doc(hidden)]
pub mod peer;
#[doc(hidden)]
pub mod peer_dos;
#[doc(hidden)]
pub mod peers;
#[doc(hidden)]
pub mod perf_meter;
#[doc(hidden)]
pub mod reactor;
#[doc(hidden)]
pub mod seeds;
#[doc(hidden)]
pub mod serve_perf;
#[doc(hidden)]
pub mod service;
#[doc(hidden)]
pub mod socks;
#[doc(hidden)]
pub mod tip_accept;
#[doc(hidden)]
pub mod tx_relay;
#[doc(hidden)]
pub mod v2;
#[doc(hidden)]
pub mod versionbits_warn;

pub use asmap::{
    AsMap, ASMAP_EIGHT_TRAILING_ZEROS, ASMAP_JUMP_OFF_END, ASMAP_JUMP_PAST_FILE,
    ASMAP_JUMP_SHORT_TAIL, ASMAP_MATCH_PAST_END, ASMAP_SECOND_DEFAULT, ASMAP_TRAILING_ONE,
    ASMAP_TWO_SHORT_MATCHES, LONE_RETURN_ASMAP, LOOPBACK_ASMAP, TWO_PREFIX_ASMAP,
};
pub use cache::BlockCache;
pub use chain::{check_block_proposal_with, AcceptOutcome, ChainHub, ChainTipInfo, TipEvent};
pub use compact::{
    classify_v2_cmpct_peer, cmpct_init_data_ok, shortid_map_from_txs, try_reconstruct,
    v2_header_hashes, CmpctPeerFrame,
};
pub use ephemeral::spawn_isolated_broadcast_loop;
pub use error::NetError;
pub use eviction::{select_inbound_eviction, InboundEvictCandidate};
pub use i2p_sam::{i2p_addr_from_sam_b64, I2pSam, SAM_RETRY, SAM_RETRY_TEST};
pub use most_work::{sum_work, WorkOverflow};
pub use msg_decode::{
    block_decode_permits, block_decode_permits_for, blocking_pool_size, blocking_pool_size_for,
    ctrl_decode_permits, ctrl_decode_permits_for, MIN_BLOCKING_POOL,
};
pub use net_permissions::{
    apply_implicit, parse_whitebind, parse_whitelist, NetPermTable, NetPermissionFlags,
    WhitebindGrant, WhitelistGrant, DEFAULT_WHITELISTFORCERELAY, DEFAULT_WHITELISTRELAY,
};
pub use netaddr::{is_cjdns_ip, NetAddr, OnlyNet};
pub use netgroup::netgroup;
pub use peer::{
    drain_pending_now, flush_tx_invs, force_announce_txid, local_service_flags, run_feeler_timed,
    PendingBlocks, V2PlainSession, MAX_SERVE_BLOCKS,
};
pub use peer_dos::DEFAULT_MAX_INBOUND;
pub use peers::{
    connection_counts, outbound_time_offset, parse_peer_addr, parse_peer_addr_with_port,
    parse_peer_net, pick_stale_follow_evict, DialReady, DialRequest, DialTarget, LivePeer,
    PeerConnType, PeerHub, PeerInfo, PeerOut,
};
pub use perf_meter::RequestMeter;
pub use rbitcoin_mempool::MempoolGraphStats;
pub use rbitcoin_mempool::{AcceptError, AcceptResult, SelectBudget, Selected};
pub use reactor::{off_pool, BlockingRegion};
pub use seeds::{
    default_port, default_rpc_port, dns_seeds, resolve_dns_seeds, socks_dns_seed_dests, AddrMan,
    PeerEntry, PeerFlags, MAX_ADDR_MAN,
};
pub use serve_perf::{
    format_serve_perf, sample_reset_serve_perf, serve_perf_totals, ServePerfSample,
};
pub use service::{P2PNode, REDIAL_INTERVAL, REDIAL_INTERVAL_TEST};
pub use socks::{install_i2p_dialer, Dialer, NetProxies};
pub use tx_relay::{
    ElectrumMempoolItem, FeeHistoryBackfillStats, MempoolAnnounce, MempoolHub, MempoolPerfSample,
    MempoolTxSnapEntry, MempoolTxSnapshot,
};
pub use v2::{encode_v2_contents, parse_v2_regtest, parse_v2_regtest_named, WireBytes};
pub use versionbits_warn::{trust_warning_line, versionbit_warning_strings};

/// Default number of **live download peers** during IBD
/// (`rbitcoin_ibd::IbdConfig::target_peers` and node `--max-outbound` default).
///
/// This is **not** the seed candidate pool size. The node dials a larger sample
/// of seed addresses (typically `2 × target`, clamped) so failed connects still
/// leave enough live peers.
pub const DEFAULT_IBD_TARGET_PEERS: u32 = 16;
