use rbitcoin_ibd::IbdConfig;
use rbitcoin_net::{AddrMan, Dialer, PeerConnType, TipEvent};
use rbitcoin_node::config::{parse_btc_to_sat, NodeConfig};
use rbitcoin_node::run::*;
use rbitcoin_query::Query;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
fn tiny_regtest(dir: impl AsRef<std::path::Path>) -> NodeConfig {
    NodeConfig::default()
        .with_datadir(dir.as_ref())
        .with_network(rbitcoin_primitives::Network::Regtest)
        .with_tiny_heads()
}

/// Perf (5s) and RPC-stop (50ms) ticks must still evaluate stale redial.
/// A one-shot sleep in the same `select!` is reset on every such wake.
/// `--sh-index` off still binds Electrum/Esplora. Address methods fail
/// closed inside the servers; the listeners themselves are not the gate.
#[test]
fn listeners_ready_without_sh_index() {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-shoff-listen-{n}"));
    let _ = std::fs::remove_dir_all(&dir);
    let q = Query::open_or_create_tiny(dir.join("store")).unwrap();
    let gates = enter_tip_mode(&q, None, false);
    assert!(gates.tip_follow_ready);
    assert!(
        gates.sh_tip_ready,
        "Electrum/Esplora bind when --sh-index is off"
    );
    assert!(!q.sh_index_enabled());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stale_follow_needs_room_at_max_outbound() {
    assert!(!stale_follow_needs_room(0, 16));
    assert!(!stale_follow_needs_room(15, 16));
    assert!(stale_follow_needs_room(16, 16));
    assert!(stale_follow_needs_room(31, 16));
    assert!(stale_follow_needs_room(1, 1));
    assert!(!stale_follow_needs_room(0, 1));
}

/// `--proxy` or `--onion` with `--trust-peer` must not turn on isolated
/// broadcast. This node's own txs go out on the standing session.
#[test]
fn review_trust_proxy_uses_standing_relay() {
    let mut cfg = NodeConfig::default();
    assert!(!proxy_or_onion_without_trust(&cfg));
    let socks: SocketAddr = "127.0.0.1:9050".parse().unwrap();
    cfg.listen.proxy = Some(socks);
    assert!(proxy_or_onion_without_trust(&cfg));
    cfg.listen.proxy = None;
    cfg.listen.onion = Some(socks);
    assert!(proxy_or_onion_without_trust(&cfg));
    cfg.trust_peer = Some(rbitcoin_net::NetAddr::Ip("192.0.2.1:8333".parse().unwrap()));
    assert!(!proxy_or_onion_without_trust(&cfg));
    cfg.listen.onion = None;
    cfg.listen.proxy = Some(socks);
    assert!(!proxy_or_onion_without_trust(&cfg));
}

#[test]
fn trust_peer_dials_only_that_peer() {
    use rbitcoin_node::cli::{operator_config_from_args, OperatorArgs};
    use rbitcoin_node::config::P2pListen;
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-trust-dial-{n}"));
    let addr = "192.0.2.1:8333";
    let cfg = match operator_config_from_args([
        "rbitcoin-node",
        "--datadir",
        dir.to_str().unwrap(),
        "--network",
        "regtest",
        "--trust-peer",
        addr,
    ]) {
        Ok(OperatorArgs::Ready { config, .. }) => config,
        other => panic!("expected config, got {other:?}"),
    };
    assert!(cfg.trust_peer_set());
    assert!(matches!(cfg.listen.p2p, P2pListen::Off));
    assert_eq!(cfg.listen.max_inbound, 0);
    assert!(!cfg.listen.use_seeds);
    assert!(!should_resolve_default_seeds(&cfg));
    assert!(!seednodes_allowed(&cfg.listen));
    let mut book = AddrMan::new();
    book.add("198.51.100.9:8333".parse().unwrap());
    book.add(addr.parse().unwrap());
    let got = outbound_dial_targets(true, &cfg.listen.connect, &book, 8, &[]);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].to_string(), addr);
    let unresolved = outbound_dial_targets(true, &[], &book, 8, &[]);
    assert!(
        unresolved.is_empty(),
        "unresolved trust-peer must not dial the peers file"
    );
    let open = follow_dial_targets(&[], &book, 8, &[]);
    assert!(
        !open.is_empty(),
        "the peers file is still a dial target when trust-peer is off"
    );
    let shared = std::sync::Arc::new(std::sync::Mutex::new(book));
    let pinned = rbitcoin_net::NetAddr::Ip(addr.parse().unwrap());
    let trust_book = rbitcoin_ibd::PeerBookSession::new(ibd_shared_peers(true, &shared), &[pinned]);
    let trust_cands = trust_book
        .book()
        .take_dial_candidates_net(8, &Default::default(), &[]);
    assert_eq!(trust_cands, vec![pinned], "{trust_cands:?}");
    let open_book = rbitcoin_ibd::PeerBookSession::new(ibd_shared_peers(false, &shared), &[]);
    let open_cands = open_book
        .book()
        .take_dial_candidates_net(8, &Default::default(), &[]);
    assert!(
        open_cands
            .iter()
            .any(|a| a.to_string() == "198.51.100.9:8333"),
        "flag off still dials the peers file: {open_cands:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn follow_dial_targets_connect_bypasses_diversity() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let mut am = AddrMan::new();
    am.add(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 0, 1)), 8333));
    am.add(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 0, 1)), 8333));
    let connect = vec![rbitcoin_net::NetAddr::Ip(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        8333,
    ))];
    let occupied = vec![rbitcoin_net::NetAddr::Ip(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(1, 2, 0, 9)),
        8333,
    ))];
    let want = vec![rbitcoin_net::NetAddr::Ip(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        8333,
    ))];
    assert_eq!(follow_dial_targets(&connect, &am, 8, &occupied), want);
    // Core reports `-connect` peers as `manual`; addrman picks are full relay.
    assert_eq!(follow_dial_type(&connect), PeerConnType::Manual);
    assert_eq!(follow_dial_type(&[]), PeerConnType::OutboundFullRelay);
}

#[test]
fn seednode_delay_starts_at_the_first_dial() {
    assert!(
        !seednode_delay_elapsed(0, 1_700_000_011),
        "no dial yet, so a clock jump must not add the seednode"
    );
    let started = 1_700_000_000u64;
    assert!(
        !seednode_delay_elapsed(started, started),
        "the dial itself must not add the seednode"
    );
    assert!(
        !seednode_delay_elapsed(started, started + 9),
        "nine seconds is still inside the addrman window"
    );
    assert!(
        seednode_delay_elapsed(started, started + 11),
        "setmocktime(now+11) after the dial must open the window"
    );
}

#[test]
fn seednodes_are_off_under_connect() {
    let mut listen = NodeConfig::default().listen;
    assert!(!seednodes_allowed(&listen), "no seednodes");
    listen.seednodes = vec!["127.0.0.1:18444".into()];
    assert!(seednodes_allowed(&listen));
    listen.connect = vec![rbitcoin_net::NetAddr::Ip(
        "127.0.0.1:18445".parse().unwrap(),
    )];
    assert!(
        !seednodes_allowed(&listen),
        "Core skips seednodes under -connect"
    );
    listen.connect.clear();
    listen.connect_dns = vec!["localhost:18445".into()];
    assert!(!seednodes_allowed(&listen), "a --connect hostname pins too");
}

#[test]
fn follow_dial_targets_keeps_i2p_connect() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let mut am = AddrMan::new();
    am.add(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 0, 1)), 8333));
    let i2p = rbitcoin_net::NetAddr::I2p {
        dest: [7u8; 32],
        port: 8333,
    };
    let connect = vec![i2p];
    let got = follow_dial_targets(&connect, &am, 8, &[]);
    assert_eq!(got, vec![i2p]);
}

#[test]
fn follow_dial_targets_skips_occupied_group() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let mut am = AddrMan::new();
    let same = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 0, 1)), 8333);
    let other = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 3, 0, 1)), 8333);
    am.add(same);
    am.add(other);
    let occupied = vec![rbitcoin_net::NetAddr::Ip(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(1, 2, 0, 9)),
        8333,
    ))];
    let got = follow_dial_targets(&[], &am, 1, &occupied);
    assert_eq!(got, vec![rbitcoin_net::NetAddr::Ip(other)]);
}

#[test]
fn follow_dial_targets_picks_addrman_onion() {
    let onion: rbitcoin_net::NetAddr =
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
            .parse()
            .unwrap();
    let mut am = AddrMan::new();
    am.set_onion_reachable(true);
    am.set_only_net(vec![rbitcoin_net::OnlyNet::Onion]);
    am.add_addr(onion);
    assert_eq!(follow_dial_targets(&[], &am, 1, &[]), vec![onion]);
    assert!(
        follow_dial_targets(&[], &am, 1, &[onion]).is_empty(),
        "live onion net must not be re-dialed via 0.0.0.0 hint"
    );
}

#[test]
fn tip_follow_checks_stale_on_perf_and_rpc_stop() {
    assert!(
        tip_follow_checks_stale(TipFollowWakeKind::Perf),
        "5s tip:perf tick must still consider a stale extra outbound"
    );
    assert!(
        tip_follow_checks_stale(TipFollowWakeKind::RpcStop),
        "RPC-stop tick must still consider a stale extra outbound"
    );
    assert!(tip_follow_checks_stale(TipFollowWakeKind::Poll));
    assert!(tip_follow_checks_stale(TipFollowWakeKind::TipSame));
    assert!(!tip_follow_checks_stale(TipFollowWakeKind::TipChanged));
    assert!(!tip_follow_checks_stale(TipFollowWakeKind::Stop));
}

#[test]
fn parse_blockmintxfee_btc_to_sat() {
    assert_eq!(parse_btc_to_sat("0.00000001"), Ok(1));
    assert_eq!(parse_btc_to_sat("0"), Ok(0));
    assert_eq!(parse_btc_to_sat("0.025"), Ok(2_500_000));
    assert_eq!(parse_btc_to_sat("0.00000005"), Ok(5));
    assert_eq!(parse_btc_to_sat("-0.0001"), Err("must be non-negative"));
    assert_eq!(parse_btc_to_sat("nope"), Err("invalid"));
}

/// Persistent stale interval must complete even when a faster perf tick
/// is in the same biased `select!` (the old one-shot sleep never did).
#[tokio::test]
async fn stale_interval_fires_alongside_faster_perf_tick() {
    let mut perf = tokio::time::interval(Duration::from_millis(15));
    perf.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    perf.tick().await;
    let mut stale = tokio::time::interval(Duration::from_millis(50));
    stale.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    stale.tick().await;
    let (_tx, mut tip_rx) = broadcast::channel::<TipEvent>(8);
    let start = Instant::now();
    let mut saw_poll = false;
    while start.elapsed() < Duration::from_millis(200) {
        let w = tokio::time::timeout(
            Duration::from_millis(250),
            tip_follow_next_wake(
                std::future::pending(),
                None,
                &mut perf,
                &mut tip_rx,
                &mut stale,
                None,
            ),
        )
        .await
        .expect("supervisor wake");
        if matches!(w, TipFollowWake::Poll) {
            saw_poll = true;
            break;
        }
    }
    assert!(
        saw_poll,
        "stale interval must produce Poll while perf ticks every 15ms"
    );
}

#[test]
fn catch_up_ok_genesis_zero_accepts_is_incomplete() {
    assert_eq!(catch_up_after_ok(0, 0, false), CatchUp::Incomplete);
    assert_eq!(catch_up_after_ok(3, 3, true), CatchUp::Incomplete);
}

#[test]
fn catch_up_ok_with_blocks_is_complete() {
    assert_eq!(
        catch_up_after_ok(3, 3, false),
        CatchUp::Complete {
            dial_failed_all: false
        }
    );
    assert_eq!(
        catch_up_after_ok(0, 1, false),
        CatchUp::Complete {
            dial_failed_all: false
        }
    );
    assert!(CatchUp::complete().is_complete());
    assert!(!CatchUp::complete().dial_failed_all());
    assert!(!CatchUp::Incomplete.is_complete());
}

#[test]
fn empty_targets_stay_open_until_a_dialable_address_exists() {
    assert!(catch_up_without_targets(false).is_complete());
    assert!(
        !catch_up_without_targets(true).is_complete(),
        "a swept or seed-pending book is not caught up"
    );
}

#[test]
fn catch_up_err_with_tip_indexes_dials_failed() {
    assert_eq!(
        catch_up_after_err(10, true, false),
        CatchUp::Complete {
            dial_failed_all: true
        }
    );
    assert!(CatchUp::complete_dial_failed().dial_failed_all());
    assert_eq!(catch_up_after_err(10, false, false), CatchUp::Incomplete);
    assert_eq!(catch_up_after_err(0, true, false), CatchUp::Incomplete);
    assert_eq!(catch_up_after_err(10, true, true), CatchUp::Incomplete);
}

#[test]
fn connect_genesis_incomplete_enters_tip_follow() {
    assert_eq!(
        catch_up_with_connect(CatchUp::Incomplete, true, false, 0),
        CatchUp::complete_dial_failed()
    );
    assert_eq!(
        catch_up_with_connect(CatchUp::Incomplete, false, false, 0),
        CatchUp::Incomplete
    );
    assert_eq!(
        catch_up_with_connect(CatchUp::Incomplete, true, true, 0),
        CatchUp::Incomplete
    );
    assert!(catch_up_with_connect(CatchUp::complete(), true, false, 0).is_complete());
}

#[test]
fn connect_nongenesis_incomplete_stays_in_ibd() {
    assert_eq!(
        catch_up_with_connect(CatchUp::Incomplete, true, false, 50),
        CatchUp::Incomplete
    );
}

#[test]
fn relay_requires_min_chain_work_even_when_following() {
    assert!(!relay_while_following(false, false, false));
    assert!(relay_while_following(true, false, false));
    assert!(!relay_while_following(true, true, false));
    assert!(!relay_while_following(true, false, true));
    let mut cfg = NodeConfig::default();
    assert!(cfg.meets_minimum_chain_work([0; 32]));
    cfg.minimum_chain_work = Some([0xff; 32]);
    assert!(
        !cfg.meets_minimum_chain_work([0; 32]),
        "a non-genesis tip under --min-chain-work follows, but relay stays gated"
    );
}

#[test]
fn cjdns_listen_is_advertised_without_external_ip() {
    use std::net::{IpAddr, Ipv6Addr};
    let fc = Ipv6Addr::new(0xfc00, 1, 2, 3, 4, 5, 6, 7);
    let bind = SocketAddr::from((fc, 8333));
    let got = external_ips_with_cjdns_bind(&[], bind, true);
    assert_eq!(got, vec![IpAddr::V6(fc)]);
    assert!(
        external_ips_with_cjdns_bind(&[], bind, false).is_empty(),
        "fc00 stays unroutable until --cjdns-reachable"
    );
    let v4 = SocketAddr::from(([1, 2, 3, 4], 8333));
    assert!(external_ips_with_cjdns_bind(&[], v4, true).is_empty());
    let ula = SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1), 8333));
    assert!(
        external_ips_with_cjdns_bind(&[], ula, true).is_empty(),
        "fd00::/8 is not CJDNS"
    );
    let dup = external_ips_with_cjdns_bind(&[IpAddr::V6(fc)], bind, true);
    assert_eq!(dup, vec![IpAddr::V6(fc)]);
}

#[test]
fn follow_connect_timeout_i2p_is_longer_than_clearnet() {
    let i2p = rbitcoin_net::NetAddr::I2p {
        dest: [0u8; 32],
        port: 1,
    };
    let ip: rbitcoin_net::NetAddr = "127.0.0.1:1".parse().unwrap();
    assert_eq!(
        follow_connect_timeout(&Dialer::Direct, ip),
        Duration::from_secs(FOLLOW_CONNECT_SECS)
    );
    assert_eq!(
        follow_connect_timeout(&Dialer::Direct, i2p),
        Duration::from_secs(90)
    );
}

#[test]
fn catch_up_retry_config_uses_production_not_for_test() {
    let peers = std::sync::Arc::new(std::sync::Mutex::new(rbitcoin_net::AddrMan::new()));
    let cfg = catch_up_retry_config(std::sync::Arc::clone(&peers), Dialer::Direct);
    let prod = IbdConfig::default();
    let test = IbdConfig::for_test();

    assert_eq!(cfg.target_peers, 1);
    assert_eq!(
        cfg.initial_dial_waves, 1,
        "a stale-tip retry dials one wave"
    );
    assert_eq!(
        cfg.peerless,
        rbitcoin_ibd::Peerless::GiveUp,
        "the tip-follow supervisor owns the retry clock"
    );
    assert!(cfg.peers.is_some());
    // Production class (main catch-up path), not for_test knobs.
    assert_eq!(cfg.window, prod.window);
    assert_eq!(cfg.window, rbitcoin_ibd::DEFAULT_IBD_WINDOW);
    assert_eq!(cfg.per_peer, prod.per_peer);
    assert_eq!(cfg.stall, prod.stall);
    assert_eq!(cfg.connect_timeout, prod.connect_timeout);
    assert_eq!(cfg.headers_batch, prod.headers_batch);
    // Guard against reintroducing for_test() base fields.
    assert_ne!(cfg.window, test.window);
    assert_ne!(cfg.stall, test.stall);
    assert_ne!(cfg.connect_timeout, test.connect_timeout);
}

#[test]
fn startup_catch_up_waits_for_peers_only_when_a_give_up_would_exit() {
    assert_eq!(
        main_catch_up_peerless(false, None),
        rbitcoin_ibd::Peerless::Redial {
            cap: rbitcoin_ibd::PEERLESS_REDIAL_CAP
        },
        "a give-up with catch-up indexes would end the process"
    );
    assert_eq!(
        main_catch_up_peerless(true, None),
        rbitcoin_ibd::Peerless::GiveUp,
        "a give-up with tip indexes enters tip follow"
    );
    assert_eq!(
        main_catch_up_peerless(false, Some(0)),
        rbitcoin_ibd::Peerless::GiveUp,
        "a capped run returns to its caller"
    );
}

#[test]
fn follow_targets_refresh_after_catch_up_learns_peers() {
    let shared = Arc::new(std::sync::Mutex::new(AddrMan::new()));
    let mut addrman = AddrMan::new();
    assert!(
        refresh_follow_targets(false, &[], &shared, &mut addrman, 2, &[]).is_empty(),
        "empty book has no follow targets"
    );
    shared
        .lock()
        .unwrap()
        .add_addr(rbitcoin_net::NetAddr::Ip("127.0.0.1:1".parse().unwrap()));
    assert_eq!(
        refresh_follow_targets(false, &[], &shared, &mut addrman, 2, &[]).len(),
        1,
        "tip follow must see a peer learned during catch-up"
    );
    assert!(
        refresh_follow_targets(true, &[], &shared, &mut addrman, 2, &[]).is_empty(),
        "trust-peer does not follow a peer the book learned"
    );
}

#[tokio::test]
async fn empty_book_waits_for_a_discovered_target() {
    let shared = Arc::new(std::sync::Mutex::new(AddrMan::new()));
    let shutdown = Shutdown::new();
    let peers = Arc::new(rbitcoin_net::PeerHub::new());
    let shared_task = Arc::clone(&shared);
    let shutdown_task = Arc::clone(&shutdown);
    let peers_task = Arc::clone(&peers);
    let task = tokio::spawn(async move {
        let mut book = AddrMan::new();
        wait_for_dialable_targets(
            &peers_task,
            &shared_task,
            &mut book,
            &[],
            2,
            &[],
            &shutdown_task,
            false,
            rbitcoin_primitives::Network::Regtest,
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        !task.is_finished(),
        "an empty book with discovery in flight must stay in catch-up"
    );
    shared
        .lock()
        .unwrap()
        .add_addr(rbitcoin_net::NetAddr::Ip("127.0.0.1:1".parse().unwrap()));
    let found = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("learned target wakes catch-up")
        .expect("wait task");
    assert_eq!(found.expect("dial targets").len(), 1);

    let shutdown = Shutdown::new();
    shutdown.request();
    let peers = Arc::new(rbitcoin_net::PeerHub::new());
    let shared = Arc::new(std::sync::Mutex::new(AddrMan::new()));
    let mut book = AddrMan::new();
    assert!(
        wait_for_dialable_targets(
            &peers,
            &shared,
            &mut book,
            &[],
            2,
            &[],
            &shutdown,
            false,
            rbitcoin_primitives::Network::Regtest,
        )
        .await
        .is_none(),
        "shutdown ends the empty-book wait"
    );
}

#[test]
fn custom_signet_does_not_use_default_signet_seeds() {
    let mut cfg = NodeConfig::default().with_network(rbitcoin_primitives::Network::Signet);
    assert!(should_resolve_default_seeds(&cfg));
    cfg.signet_challenge = Some(bitcoin::ScriptBuf::from_bytes(vec![0x51]));
    assert!(!should_resolve_default_seeds(&cfg));
}

#[test]
fn dns_seeds_not_resolved_locally_when_proxy() {
    let mut cfg = NodeConfig::default();
    assert!(should_resolve_default_seeds(&cfg));
    cfg.listen.proxy = Some("127.0.0.1:9050".parse().unwrap());
    assert!(
        !should_resolve_default_seeds(&cfg),
        "proxy path must not ToSocketAddrs DNS/fixed seeds"
    );
}

#[test]
fn proxy_seed_bootstrap_queues_domain_addrfetch() {
    let peers = rbitcoin_net::PeerHub::new();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<rbitcoin_net::DialRequest>();
    peers.set_dialer(tx);
    let n = queue_proxy_seed_addrfetch(&peers, rbitcoin_primitives::Network::Signet);
    assert_eq!(n, 1, "signet has one default DNS seed");
    let req = rx.try_recv().expect("queued dial request");
    assert_eq!(req.typ, PeerConnType::AddrFetch);
    match req.target {
        rbitcoin_net::DialTarget::Domain { host, port } => {
            assert_eq!(host, "seed.signet.bitcoin.sprovoost.nl");
            assert_eq!(port, 38333);
        }
        other => panic!("expected domain target, got {other:?}"),
    }
}

#[test]
fn shutdown_flag_and_node_handle_smoke() {
    let sd = Shutdown::new();
    assert!(!sd.requested());
    sd.request();
    assert!(sd.requested());
    sd.request();
    assert!(sd.requested());

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-run-node-{nanos}"));
    let cfg = tiny_regtest(&dir);
    let handle = run_node(cfg).expect("run_node");
    assert_eq!(handle.network_name(), "regtest");
    assert_eq!(
        handle.query.store().headers.head_target_slots(),
        64,
        "tiny_regtest must create Tiny header heads"
    );
    assert!(handle.mempool.is_none());
    let _ = format!("{:?}", handle);
    handle.shutdown().expect("shutdown flush");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cancelled_completes_after_request() {
    let sd = Shutdown::new();
    // Already-requested path returns immediately.
    sd.request();
    sd.cancelled().await;

    let sd2 = Shutdown::new();
    let s2 = Arc::clone(&sd2);
    let j = tokio::spawn(async move {
        s2.cancelled().await;
    });
    // Give the task a chance to park on notify.
    tokio::task::yield_now().await;
    sd2.request();
    j.await.unwrap();
}

/// The `IbdConfig` literal in `run_ibd_or_skip` is not built by the config
/// journey, so this drives `run_p2p`. A refused connect must flush a fail
/// mark into the saved book, and the SOCKS proxy must be the socket dialed.
#[tokio::test]
async fn run_p2p_refused_connect_flushes_book_and_dials_proxy() {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, Ordering};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-run-p2p-proxy-{nanos}"));
    let proxy_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = proxy_l.local_addr().unwrap();
    let target_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let connect = target_l.local_addr().unwrap();
    let proxy_hit = Arc::new(AtomicBool::new(false));
    let target_hit = Arc::new(AtomicBool::new(false));
    let proxy_flag = Arc::clone(&proxy_hit);
    let target_flag = Arc::clone(&target_hit);
    std::thread::spawn(move || {
        while let Ok((mut sock, _)) = proxy_l.accept() {
            proxy_flag.store(true, Ordering::SeqCst);
            let _ = sock.set_read_timeout(Some(Duration::from_millis(200)));
            let mut buf = [0u8; 16];
            let _ = sock.read(&mut buf);
            // No acceptable SOCKS method: the dial fails before CONNECT.
            let _ = sock.write_all(&[0x05, 0xFF]);
        }
    });
    std::thread::spawn(move || {
        while target_l.accept().is_ok() {
            target_flag.store(true, Ordering::SeqCst);
        }
    });

    let mut cfg = tiny_regtest(&dir).with_p2p_listen("127.0.0.1:0".parse().unwrap());
    cfg.listen.use_seeds = false;
    cfg.listen.connect = vec![rbitcoin_net::NetAddr::from_socket(connect)];
    cfg.listen.proxy = Some(proxy);
    cfg.max_run_secs = Some(0);
    let result = tokio::time::timeout(Duration::from_secs(20), run_p2p(cfg)).await;
    assert!(result.is_ok(), "run_p2p timed out");
    let _ = result.unwrap();

    assert!(
        proxy_hit.load(Ordering::SeqCst),
        "IBD must dial the configured SOCKS proxy"
    );
    assert!(
        !target_hit.load(Ordering::SeqCst),
        "SOCKS dial must not open a direct TCP connection to the target"
    );
    let peers_path = dir.join("peers");
    let text = std::fs::read_to_string(&peers_path).expect("peers saved");
    let row = text
        .lines()
        .find(|line| line.starts_with(&format!("{connect} ")))
        .unwrap_or_else(|| {
            panic!("IBD must flush the dial failure into the saved peer book\n{text}")
        });
    let flags = row
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.strip_prefix("0x"))
        .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        .unwrap_or(0);
    assert!(
        flags & rbitcoin_net::PeerFlags::FAILED_LAST_CONNECT != 0,
        "IBD must flush the dial failure into the saved peer book, row {row}"
    );
    let book = AddrMan::load(&peers_path).expect("peers saved");
    assert!(
        book.entry_of(&rbitcoin_net::NetAddr::from_socket(connect))
            .is_none(),
        "loopback is not restored from the peers file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn node_handle_shutdown_with_mempool() {
    use rbitcoin_net::MempoolHub;
    use std::sync::Arc;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-handle-mp-{nanos}"));
    let cfg = tiny_regtest(&dir);
    let mut handle = run_node(cfg).expect("run_node");
    // Dual-open same store for MempoolHub's Arc<Query> (flush only).
    // Same layout as run_node — Tiny here, Mainnet would mismatch.
    let q = Arc::new(Query::open_or_create_layout(handle.config.store_layout()).unwrap());
    let mp = MempoolHub::open(handle.config.mempool_path(), q).expect("mempool");
    handle.mempool = Some(mp);
    let _ = format!("{:?}", handle);
    handle.shutdown().expect("flush query+mempool");
    let _ = std::fs::remove_dir_all(&dir);
}

fn scratch_dir(label: &str) -> std::path::PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-{label}-{n}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn startup_sets_datadir_hdd_on_the_store() {
    let dir = scratch_dir("datadir-hdd");
    let q = Query::open_or_create_tiny(&dir).unwrap();
    assert!(!q.store().datadir_hdd());
    let mut cfg = NodeConfig::default();
    cfg.datadir_hdd = true;
    apply_startup_index_mode(&q, &cfg, 0).unwrap();
    assert!(q.store().datadir_hdd());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A pack-marked head whose inclusion floor is behind the tip must not open
/// Electrum. Tip follow still starts so write-behind can catch up.
#[test]
fn enter_tip_mode_does_not_ready_electrum_when_inclusion_lags() {
    let dir = scratch_dir("tip-gate");
    let q = Query::open_or_create_tiny(&dir).unwrap();
    let bump = q.store().scripthash.alloc_bump();
    let session = q.store().scripthash.pack_shard_session(0).unwrap();
    let pack = session.finish_pack().unwrap();
    assert_eq!(pack.bump, bump);
    q.store().scripthash.publish_packed_shard(0, pack).unwrap();
    assert!(q.store().scripthash.has_durable_index());
    assert!(q.sh_use_writebehind());
    assert!(
        !q.sh_is_tip_ready(),
        "empty tip is not an inclusion-complete scripthash head"
    );
    let gates = enter_tip_mode(&q, None, true);
    assert!(gates.tip_follow_ready);
    assert!(
        !gates.sh_tip_ready,
        "lagging inclusion must not start Electrum"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Cancel before any extract file exists must not tell the operator to
/// resume from `scripthash.cold_progress`.
#[test]
fn enter_tip_mode_cancel_does_not_name_missing_cold_progress() {
    let dir = scratch_dir("tip-cancel");
    let q = Query::open_or_create_tiny(&dir).unwrap();
    assert!(!q.store().path().join("scripthash.cold_progress").is_file());
    assert!(!q.store().path().join("scripthash.unsorted").is_dir());
    let cancel = Arc::new(AtomicBool::new(true));
    rbitcoin_log::capture_logs(true);
    let gates = enter_tip_mode(&q, Some(cancel), true);
    let lines = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    assert!(gates.tip_follow_ready);
    assert!(!gates.sh_tip_ready);
    let joined = lines
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !joined.contains("scripthash.cold_progress"),
        "cancel warn named a resume file that is not on disk:\n{joined}"
    );
    assert!(
        joined.contains("cancelled before a durable scripthash extract"),
        "cancel warn should name the phase that actually exists:\n{joined}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn max_run_deadline_wakes_without_the_perf_tick() {
    let mut perf = tokio::time::interval(Duration::from_secs(30));
    perf.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    perf.tick().await;
    let mut stale = tokio::time::interval(Duration::from_secs(30));
    stale.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    stale.tick().await;
    let (_tx, mut tip_rx) = broadcast::channel::<TipEvent>(8);
    let start = Instant::now();
    let wake = tokio::time::timeout(
        Duration::from_millis(500),
        tip_follow_next_wake(
            std::future::pending(),
            None,
            &mut perf,
            &mut tip_rx,
            &mut stale,
            Some(Instant::now() + Duration::from_millis(40)),
        ),
    )
    .await
    .expect("deadline must wake before the perf tick");
    assert!(matches!(wake, TipFollowWake::Stop));
    assert!(start.elapsed() < Duration::from_millis(200));
}

/// A fresh `--proxy` datadir has no targets until a seed's `getaddr`
/// reply is learned. The wait re-queues the seeds while no addr-fetch
/// session is live, ignores a book filled only by a self-announce, and
/// ends on that reply, shutdown, or its deadline.
///
/// The clock is paused. Polls still happen before the 400 ms deadline, so
/// a self-announce cannot pass as a reply, and that wait is not wall time.
#[tokio::test(start_paused = true)]
async fn proxy_seed_wait_ends_on_a_learned_reply_shutdown_or_deadline() {
    use std::sync::atomic::{AtomicU64, Ordering};

    let peers = rbitcoin_net::PeerHub::new();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<rbitcoin_net::DialRequest>();
    peers.set_dialer(tx);
    let signet = rbitcoin_primitives::Network::Signet;
    let shared = Arc::new(std::sync::Mutex::new(AddrMan::new()));
    let announced: rbitcoin_net::NetAddr = "1.2.3.4:38333".parse().unwrap();
    shared.lock().unwrap().add_addr(announced);
    let replies = Arc::new(AtomicU64::new(0));
    let sd = Shutdown::new();
    let short = Duration::from_millis(50);

    let at = std::net::SocketAddr::from(([127, 0, 0, 1], 38333));
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: bitcoin::p2p::PROTOCOL_VERSION,
        services: bitcoin::p2p::ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: bitcoin::p2p::Address::new(&at, bitcoin::p2p::ServiceFlags::NONE),
        sender: bitcoin::p2p::Address::new(&at, bitcoin::p2p::ServiceFlags::NONE),
        nonce: 0,
        user_agent: "/seed:0/".into(),
        start_height: 0,
        relay: true,
    };
    let answering = peers.register(at, at, &ver, false, PeerConnType::AddrFetch);
    let counted = Arc::clone(&replies);
    let timed_out = await_proxy_seed_book(
        &peers,
        signet,
        &shared,
        &sd,
        move || counted.load(Ordering::SeqCst),
        short,
        Duration::from_millis(400),
    )
    .await;
    assert!(
        timed_out.is_none(),
        "a self-announce alone is not the reply"
    );
    assert!(
        rx.try_recv().is_err(),
        "a live addr-fetch session is not re-queued"
    );
    peers.unregister(answering.id);

    let seed = {
        let (shared, replies) = (Arc::clone(&shared), Arc::clone(&replies));
        tokio::spawn(async move {
            let req = rx.recv().await.expect("seed addr-fetch re-queued");
            assert_eq!(req.typ, PeerConnType::AddrFetch);
            shared
                .lock()
                .unwrap()
                .add_addr("5.6.7.8:38333".parse().unwrap());
            replies.fetch_add(1, Ordering::SeqCst);
        })
    };
    let counted = Arc::clone(&replies);
    let book = tokio::time::timeout(
        Duration::from_secs(5),
        await_proxy_seed_book(
            &peers,
            signet,
            &shared,
            &sd,
            move || counted.load(Ordering::SeqCst),
            short,
            Duration::from_secs(60),
        ),
    )
    .await
    .expect("the wait ends once a reply is learned")
    .expect("no shutdown and no deadline");
    seed.await.unwrap();
    assert_eq!(book.len(), 2);

    sd.request();
    let counted = Arc::clone(&replies);
    let book = await_proxy_seed_book(
        &peers,
        signet,
        &shared,
        &sd,
        move || counted.load(Ordering::SeqCst),
        Duration::from_secs(60),
        Duration::from_secs(60),
    )
    .await;
    assert!(book.is_none(), "shutdown ends the wait with no book");
}
