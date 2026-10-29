use bitcoin::hashes::Hash;
use bitcoin::p2p::Magic;
use bitcoin::BlockHash;
use rbitcoin_ibd::ibd::dial::*;
use rbitcoin_ibd::ibd::peer_io::solicit_track;
use rbitcoin_ibd::ibd::peer_io::{ibd_mono_ms, PeerEventSinks, PeerSlot};
use rbitcoin_ibd::ibd::rate::RELSLOW_ACTIVE_MS;
use rbitcoin_net::error::NetError;
use rbitcoin_net::seeds::AddrMan;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicU64;

fn addr(o: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, o)), 8333)
}

/// A wave of isolated SOCKS dials queues on Tor circuit builds for longer
/// than a clearnet RTT; I2P waits on tunnels and leasesets. A base above
/// a floor is kept.
#[test]
fn overlay_and_socks_connects_outlast_a_direct_one() {
    let i2p = rbitcoin_net::NetAddr::I2p {
        dest: [0u8; 32],
        port: 1,
    };
    let onion: rbitcoin_net::NetAddr =
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
            .parse()
            .unwrap();
    let ip: rbitcoin_net::NetAddr = "127.0.0.1:1".parse().unwrap();
    let cjdns = rbitcoin_net::NetAddr::Cjdns {
        ip: std::net::Ipv6Addr::new(0xfc00, 1, 2, 3, 4, 5, 6, 7),
        port: 8333,
    };
    let tor: SocketAddr = "127.0.0.1:9050".parse().unwrap();
    let base = Duration::from_secs(8);
    let socks = Duration::from_secs(30);
    let direct = rbitcoin_net::Dialer::Direct;
    let proxied = rbitcoin_net::Dialer::socks(tor, true);
    let onion_only = rbitcoin_net::Dialer::with_proxies(None, Some(tor), true);
    assert_eq!(direct.connect_timeout(ip, base), base);
    assert_eq!(direct.connect_timeout(cjdns, base), base);
    assert_eq!(onion_only.connect_timeout(ip, base), base);
    assert_eq!(proxied.connect_timeout(cjdns, base), base);
    assert_eq!(proxied.connect_timeout(ip, base), socks);
    assert_eq!(onion_only.connect_timeout(onion, base), socks);
    assert_eq!(proxied.connect_timeout(onion, base), socks);
    assert_eq!(direct.connect_timeout(i2p, base), Duration::from_secs(90));
    assert_eq!(proxied.connect_timeout(i2p, base), Duration::from_secs(90));
    let long = Duration::from_secs(120);
    assert_eq!(proxied.connect_timeout(ip, long), long);
    assert_eq!(proxied.connect_timeout(i2p, long), long);
    let lowered = proxied.with_connect_floor(Duration::from_secs(2));
    assert_eq!(
        lowered.connect_timeout(ip, Duration::from_secs(1)),
        Duration::from_secs(2)
    );
    assert_eq!(
        lowered.connect_timeout(ip, base),
        Duration::from_secs(2),
        "a floor under 30s is the stalled-proxy bound"
    );
}

fn dummy_slot(id: usize, a: SocketAddr, alive: bool) -> PeerSlot {
    let (cmd_tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    // JoinHandle without a running runtime: abort on Drop is still safe.
    let task = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .spawn(async {});
    PeerSlot {
        id,
        addr: a,
        net: rbitcoin_net::NetAddr::from_socket(a),
        cmd_tx,
        in_flight: HashSet::new(),
        requested: solicit_track().0,
        solicited_bytes: solicit_track().1,
        solicited_ms: solicit_track().2,
        any_rx_ms: Arc::new(AtomicU64::new(0)),
        getdata_wire: rbitcoin_ibd::ibd::peer_io::GetdataWire::new(),
        peer_height: 0,
        connected_ms: 0,
        first_data_ms: 0,
        bytes_rx_total: Arc::new(AtomicU64::new(0)),
        rate: Default::default(),
        chain: Default::default(),
        alive,
        task,
    }
}

#[test]
fn onion_stall_kicks_keep_independent_cooldowns_and_strikes() {
    let now = Instant::now();
    let onions = [
        rbitcoin_net::NetAddr::Onion {
            pk: [1; 32],
            port: 8333,
        },
        rbitcoin_net::NetAddr::Onion {
            pk: [2; 32],
            port: 8333,
        },
    ];
    let mut cooldown = HashMap::new();
    let mut strikes = HashMap::new();
    for (id, net) in [onions[0], onions[1], onions[0]].into_iter().enumerate() {
        let mut slot = dummy_slot(id, "0.0.0.0:8333".parse().unwrap(), true);
        slot.net = net;
        let h = hash_byte(id as u8);
        put_on_wire(&mut slot, h, 0);
        let mut inflight = HashMap::from([(h, rbitcoin_ibd::ibd::state::InflightReq::new(id))]);
        let freed = disconnect_stalled_block_peers_at(
            std::slice::from_mut(&mut slot),
            &mut inflight,
            &mut rbitcoin_ibd::ibd::body::BodyPresence::new(),
            &mut cooldown,
            &mut strikes,
            now,
            Duration::from_secs(30),
            60_000,
        );
        assert_eq!(freed, vec![h]);
        assert!(!slot.alive);
        let blocked = dial_blocked_addrs(&[], &cooldown, now);
        assert!(
            blocked.contains(&net),
            "kicked onion must be excluded from redial"
        );
        if id == 0 {
            assert!(
                !blocked.contains(&onions[1]),
                "another onion on the same port stays free"
            );
        }
    }
    let after_first = now + STALL_ADDR_COOLDOWN;
    expire_addr_cooldown(&mut cooldown, &mut strikes, &AddrMan::new(), after_first);
    assert_eq!(
        dial_blocked_addrs(&[], &cooldown, after_first),
        HashSet::from([onions[0]])
    );
    expire_addr_cooldown(
        &mut cooldown,
        &mut strikes,
        &AddrMan::new(),
        now + STALL_ADDR_COOLDOWN_2,
    );
    assert!(dial_blocked_addrs(&[], &cooldown, now + STALL_ADDR_COOLDOWN_2).is_empty());
}

#[test]
fn onion_dial_failure_is_excluded_until_cooldown_expires() {
    let onion = rbitcoin_net::NetAddr::Onion {
        pk: [3; 32],
        port: 8333,
    };
    let mut book = AddrMan::new();
    let mut cooldown = HashMap::new();
    let mut strikes = HashMap::new();
    let now = Instant::now();
    apply_dial_result(
        &mut book,
        &DialBatchResult {
            slots: vec![],
            failed: vec![(onion, DialFailKind::Network)],
            attempted: vec![onion],
        },
        &mut cooldown,
        &mut strikes,
        now,
    );
    assert!(dial_blocked_addrs(&[], &cooldown, now).contains(&onion));
    expire_addr_cooldown(
        &mut cooldown,
        &mut strikes,
        &book,
        now + STALL_ADDR_COOLDOWN,
    );
    assert!(!dial_blocked_addrs(&[], &cooldown, now + STALL_ADDR_COOLDOWN).contains(&onion));
}

#[test]
fn strike_history_is_reclaimed_after_addrman_eviction_and_cooldown_expiry() {
    use rbitcoin_net::NetAddr;

    let now = Instant::now();
    let identities = [
        NetAddr::Onion {
            pk: [10; 32],
            port: 8333,
        },
        NetAddr::I2p {
            dest: [11; 32],
            port: 8333,
        },
        NetAddr::from_socket(addr(12)),
        "[2606:4700::12]:8333".parse().unwrap(),
    ];
    let mut book = AddrMan::new();
    book.set_onion_reachable(true);
    book.set_i2p_reachable(true);
    let mut cooldown = HashMap::new();
    let mut strikes = HashMap::new();
    apply_dial_result(
        &mut book,
        &DialBatchResult {
            slots: vec![],
            attempted: identities.to_vec(),
            failed: identities
                .iter()
                .map(|&a| (a, DialFailKind::Network))
                .collect(),
        },
        &mut cooldown,
        &mut strikes,
        now,
    );
    for identity in &identities[..2] {
        book.evict_one(*identity);
    }
    expire_addr_cooldown(&mut cooldown, &mut strikes, &book, now);
    assert_eq!(
        strikes.len(),
        4,
        "active cooldowns keep their strike history"
    );
    expire_addr_cooldown(
        &mut cooldown,
        &mut strikes,
        &book,
        now + STALL_ADDR_COOLDOWN,
    );
    assert!(cooldown.is_empty());
    assert_eq!(
        strikes.len(),
        2,
        "expired identities evicted from addrman are reclaimed"
    );
    for identity in &identities[2..] {
        assert_eq!(
            record_stall_kick(
                &mut cooldown,
                &mut strikes,
                *identity,
                now + STALL_ADDR_COOLDOWN
            ),
            STALL_ADDR_COOLDOWN_2
        );
    }
    let redialed = dummy_slot(1, addr(12), true);
    apply_dial_result(
        &mut book,
        &DialBatchResult {
            slots: vec![redialed],
            attempted: vec![identities[2]],
            failed: vec![],
        },
        &mut cooldown,
        &mut strikes,
        now + STALL_ADDR_COOLDOWN,
    );
    assert_eq!(strikes.get(&identities[2]), Some(&2));
    assert!(!cooldown.contains_key(&identities[2]));
    book.evict_one(identities[2]);
    expire_addr_cooldown(
        &mut cooldown,
        &mut strikes,
        &book,
        now + STALL_ADDR_COOLDOWN,
    );
    assert_eq!(strikes, HashMap::from([(identities[3], 2)]));
}

#[test]
fn cooldown_selection_and_successful_redial_preserve_network_identity() {
    use rbitcoin_net::NetAddr;
    for (a, b) in [
        (
            NetAddr::Onion {
                pk: [4; 32],
                port: 8333,
            },
            NetAddr::Onion {
                pk: [5; 32],
                port: 8333,
            },
        ),
        (NetAddr::from_socket(addr(4)), NetAddr::from_socket(addr(5))),
        (
            "[2606:4700::1]:8333".parse().unwrap(),
            "[2606:4700::2]:8333".parse().unwrap(),
        ),
    ] {
        let now = Instant::now();
        let mut book = AddrMan::new();
        book.set_onion_reachable(true);
        book.add_addr(a);
        book.add_addr(b);
        let mut cooldown = HashMap::new();
        let mut strikes = HashMap::new();
        record_stall_kick(&mut cooldown, &mut strikes, a, now);
        let mut exclude = dial_blocked_addrs(&[], &cooldown, now);
        assert!(replacement_available(&book, &[], &cooldown, now));
        assert_eq!(
            admit_cooldown_fallback(&book, &mut exclude, &[], &cooldown, now, &HashSet::new()),
            None
        );
        assert!(exclude.contains(&a));
        book.note_attempt_addr(a);
        record_stall_kick(&mut cooldown, &mut strikes, b, now);
        assert!(!replacement_available(&book, &[], &cooldown, now));
        exclude = dial_blocked_addrs(&[], &cooldown, now);
        assert_eq!(
            admit_cooldown_fallback(&book, &mut exclude, &[], &cooldown, now, &HashSet::new()),
            Some(b)
        );
        assert!(exclude.contains(&a));
        assert!(!exclude.contains(&b));
        let mut held = dial_blocked_addrs(&[], &cooldown, now);
        assert_eq!(
            admit_cooldown_fallback(&book, &mut held, &[], &cooldown, now, &HashSet::from([b])),
            Some(a)
        );
        let mut slot = dummy_slot(
            1,
            b.socket_addr().unwrap_or("0.0.0.0:8333".parse().unwrap()),
            true,
        );
        slot.net = b;
        apply_dial_result(
            &mut book,
            &DialBatchResult {
                slots: vec![slot],
                failed: vec![],
                attempted: vec![b],
            },
            &mut cooldown,
            &mut strikes,
            now,
        );
        assert_eq!(dial_blocked_addrs(&[], &cooldown, now), HashSet::from([a]));
        assert_eq!(
            record_stall_kick(&mut cooldown, &mut strikes, b, now),
            STALL_ADDR_COOLDOWN_2
        );
        expire_addr_cooldown(
            &mut cooldown,
            &mut strikes,
            &book,
            now + STALL_ADDR_COOLDOWN,
        );
        assert!(replacement_available(
            &book,
            &[],
            &cooldown,
            now + STALL_ADDR_COOLDOWN
        ));
        assert_eq!(
            dial_blocked_addrs(&[], &cooldown, now + STALL_ADDR_COOLDOWN),
            HashSet::from([b])
        );
    }
}

#[test]
fn onion_relative_slow_eviction_requires_an_uncooled_replacement() {
    use rbitcoin_net::NetAddr;
    let now = Instant::now();
    let spare = NetAddr::Onion {
        pk: [99; 32],
        port: 8333,
    };
    let mut book = AddrMan::new();
    book.set_onion_reachable(true);
    book.add_addr(spare);
    let h = hash_byte(99);
    let mut slots: Vec<_> = (0..8)
        .map(|id| {
            let mut s = dummy_slot(id, "0.0.0.0:8333".parse().unwrap(), true);
            s.net = NetAddr::Onion {
                pk: [id as u8 + 1; 32],
                port: 8333,
            };
            s.first_data_ms = 1_000;
            s.rate.sample(0, 0, true);
            s.rate.sample(
                RELSLOW_ACTIVE_MS,
                if id == 0 { 4_500_000 } else { 45_000_000 },
                true,
            );
            s.in_flight.insert(h);
            s
        })
        .collect();
    let slow = slots[0].net;
    let mut cooldown = HashMap::new();
    let mut strikes = HashMap::new();
    record_stall_kick(&mut cooldown, &mut strikes, spare, now);
    let mut suspect = Some((0, 1_000));
    let mut last_kick = 0;
    let warm = 1_000 + RELATIVE_SLOW_GLOBAL_WARMUP_MS;
    let mut inflight = HashMap::from([(h, rbitcoin_ibd::ibd::state::InflightReq::new(0))]);
    let mut body = rbitcoin_ibd::ibd::body::BodyPresence::new();
    assert!(disconnect_relative_slow_block_peers_at(
        &mut slots,
        &mut inflight,
        &mut body,
        &mut cooldown,
        &mut strikes,
        now,
        &book,
        &mut suspect,
        &mut last_kick,
        warm
    )
    .is_empty());
    assert!(slots[0].alive);
    assert_eq!(suspect, None);
    let later = now + STALL_ADDR_COOLDOWN;
    expire_addr_cooldown(&mut cooldown, &mut strikes, &book, later);
    for mono in [warm, warm + RELATIVE_SLOW_HYSTERESIS_MS] {
        disconnect_relative_slow_block_peers_at(
            &mut slots,
            &mut inflight,
            &mut body,
            &mut cooldown,
            &mut strikes,
            later,
            &book,
            &mut suspect,
            &mut last_kick,
            mono,
        );
    }
    assert!(!slots[0].alive);
    assert!(inflight.is_empty());
    assert_eq!(
        dial_blocked_addrs(&[], &cooldown, later),
        HashSet::from([slow])
    );
    assert_eq!(strikes.get(&slow), Some(&1));
}

#[test]
fn classify_dial_err_network_vs_incompatible() {
    assert_eq!(
        classify_dial_err(&NetError::V1Peer),
        DialFailKind::Incompatible
    );
    assert_eq!(
        classify_dial_err(&NetError::Bip324("x".into())),
        DialFailKind::Incompatible
    );
    assert_eq!(
        classify_dial_err(&NetError::Protocol("no v2 support")),
        DialFailKind::Incompatible
    );
    assert_eq!(
        classify_dial_err(&NetError::Protocol("missing verack")),
        DialFailKind::Incompatible
    );
    assert_eq!(
        classify_dial_err(&NetError::Protocol("version too old")),
        DialFailKind::Incompatible
    );
    assert_eq!(classify_dial_err(&NetError::Timeout), DialFailKind::Network);
    assert_eq!(
        classify_dial_err(&NetError::Disconnected),
        DialFailKind::Network
    );
    assert_eq!(
        classify_dial_err(&NetError::Protocol("misbehavior")),
        DialFailKind::Network
    );
}

#[test]
fn cooldown_fallback_retries_least_recent_only_when_all_cooling() {
    let now = Instant::now();
    let mut book = AddrMan::new();
    for o in 1u8..=3 {
        book.add(addr(o));
    }
    book.note_attempt_at(addr(1), now - Duration::from_secs(10));
    book.note_attempt_at(addr(2), now - Duration::from_secs(100));
    let mut cooldown = HashMap::new();
    for o in 1u8..=3 {
        cooldown.insert(
            rbitcoin_net::NetAddr::from_socket(addr(o)),
            now + Duration::from_secs(3600),
        );
    }
    let mut exclude: HashSet<_> = (1u8..=3)
        .map(|o| rbitcoin_net::NetAddr::from_socket(addr(o)))
        .collect();
    let pick = admit_cooldown_fallback(&book, &mut exclude, &[], &cooldown, now, &HashSet::new());
    let never = rbitcoin_net::NetAddr::from_socket(addr(3));
    assert_eq!(pick, Some(never));
    assert!(!exclude.contains(&never));
    assert!(exclude.contains(&rbitcoin_net::NetAddr::from_socket(addr(1))));
    assert!(exclude.contains(&rbitcoin_net::NetAddr::from_socket(addr(2))));

    // A free address is enough; cooling peers stay blocked.
    cooldown.remove(&rbitcoin_net::NetAddr::from_socket(addr(3)));
    let pick = admit_cooldown_fallback(&book, &mut exclude, &[], &cooldown, now, &HashSet::new());
    assert_eq!(pick, None);
    assert!(!exclude.contains(&never));

    // Live never-tried peer is not the fallback; oldest attempt is.
    exclude.insert(never);
    cooldown.insert(
        rbitcoin_net::NetAddr::from_socket(addr(3)),
        now + Duration::from_secs(3600),
    );
    let live = HashSet::from([never]);
    let pick = admit_cooldown_fallback(&book, &mut exclude, &[], &cooldown, now, &live);
    assert_eq!(pick, Some(rbitcoin_net::NetAddr::from_socket(addr(2))));
    assert!(!exclude.contains(&rbitcoin_net::NetAddr::from_socket(addr(2))));

    // `until == now` has expired. It must not be treated as still cooling.
    let mut due = AddrMan::new();
    due.add(addr(4));
    due.add(addr(5));
    due.note_attempt_at(addr(5), now - Duration::from_secs(1));
    let mut due_cd = HashMap::new();
    due_cd.insert(rbitcoin_net::NetAddr::from_socket(addr(4)), now);
    due_cd.insert(rbitcoin_net::NetAddr::from_socket(addr(5)), now);
    let mut due_ex: HashSet<_> = [4u8, 5]
        .into_iter()
        .map(|o| rbitcoin_net::NetAddr::from_socket(addr(o)))
        .collect();
    let pick = admit_cooldown_fallback(&due, &mut due_ex, &[], &due_cd, now, &HashSet::new());
    assert_eq!(pick, None, "cooldown ending at now is not a fallback");
    assert!(due_ex.contains(&rbitcoin_net::NetAddr::from_socket(addr(4))));
    assert!(due_ex.contains(&rbitcoin_net::NetAddr::from_socket(addr(5))));

    // An address already in the book that this node will not dial
    // (only-net) must not win the fallback just because it was never
    // tried. `add` drops addresses that fail only-net, so restrict
    // after they are in the book.
    let mut filtered = AddrMan::new();
    for o in 6u8..=8 {
        filtered.add(addr(o));
    }
    assert_eq!(filtered.len(), 3);
    filtered.set_only_net(vec![rbitcoin_net::OnlyNet::Onion]);
    let mut filt_cd = HashMap::new();
    for o in 6u8..=8 {
        filt_cd.insert(
            rbitcoin_net::NetAddr::from_socket(addr(o)),
            now + Duration::from_secs(60),
        );
    }
    let mut filt_ex: HashSet<_> = (6u8..=8)
        .map(|o| rbitcoin_net::NetAddr::from_socket(addr(o)))
        .collect();
    let before = filt_ex.clone();
    let pick =
        admit_cooldown_fallback(&filtered, &mut filt_ex, &[], &filt_cd, now, &HashSet::new());
    assert_eq!(pick, None, "only-net hides clearnet even when cooling");
    assert_eq!(filt_ex, before);
}

#[test]
fn dial_blocked_and_cooldown_expiry() {
    let now = Instant::now();
    let s = dummy_slot(1, addr(1), true);
    let mut cooldown = HashMap::new();
    cooldown.insert(
        rbitcoin_net::NetAddr::from_socket(addr(2)),
        now + Duration::from_secs(60),
    );
    cooldown.insert(
        rbitcoin_net::NetAddr::from_socket(addr(3)),
        now - Duration::from_secs(1),
    ); // expired
    let blocked = dial_blocked_addrs(&[s], &cooldown, now);
    assert!(blocked.contains(&rbitcoin_net::NetAddr::Ip(addr(1))));
    assert!(blocked.contains(&rbitcoin_net::NetAddr::Ip(addr(2))));
    assert!(!blocked.contains(&rbitcoin_net::NetAddr::Ip(addr(3))));

    expire_addr_cooldown(&mut cooldown, &mut HashMap::new(), &AddrMan::new(), now);
    assert!(cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(addr(2))));
    assert!(!cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(addr(3))));
}

#[test]
fn handshake_then_die_is_failed_and_cooled() {
    let mut book = AddrMan::new();
    let lemon = addr(4);
    book.note_connected_addr(rbitcoin_net::NetAddr::from_socket(lemon));
    let mut cooldown = HashMap::new();
    let now = Instant::now();
    note_dead_without_block_bytes(
        &mut book,
        &mut cooldown,
        rbitcoin_net::NetAddr::Ip(lemon),
        0,
        now,
    );
    assert!(
        book.flags(&lemon).failed_last_connect(),
        "no block bytes → last-resort"
    );
    assert_eq!(book.flags(&lemon).dial_tier(), 2);
    assert!(cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(lemon)));
    let blocked = dial_blocked_addrs(&[], &cooldown, now);
    assert!(blocked.contains(&rbitcoin_net::NetAddr::Ip(lemon)));

    let good = addr(5);
    book.note_connected_addr(rbitcoin_net::NetAddr::from_socket(good));
    note_dead_without_block_bytes(
        &mut book,
        &mut cooldown,
        rbitcoin_net::NetAddr::Ip(good),
        42,
        now,
    );
    assert!(
        !book.flags(&good).failed_last_connect(),
        "peer that sent block bytes keeps its connected rank"
    );
    assert!(!cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(good)));
}

#[test]
fn misbehavior_dead_cools_after_a_block_body() {
    let mut book = AddrMan::new();
    let lemon = addr(6);
    book.note_connected_addr(rbitcoin_net::NetAddr::from_socket(lemon));
    let mut cooldown = HashMap::new();
    let now = Instant::now();
    note_misbehavior_dead(
        &mut book,
        &mut cooldown,
        rbitcoin_net::NetAddr::Ip(lemon),
        now,
    );
    assert!(
        book.flags(&lemon).failed_last_connect(),
        "a misbehavior death is a failed connect"
    );
    assert!(cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(lemon)));
    let blocked = dial_blocked_addrs(&[], &cooldown, now);
    assert!(
        blocked.contains(&rbitcoin_net::NetAddr::Ip(lemon)),
        "the dial stays cooled after a body was counted"
    );
}

fn samp(id: usize, bps: u64, inflight: bool) -> RelativeSlowSample {
    RelativeSlowSample {
        peer_id: id,
        bps,
        has_inflight: inflight,
    }
}

#[test]
fn relative_slow_pick_respects_cluster_and_outlier() {
    assert_eq!(relative_slow_pick(&[samp(0, 1_000_000, true)], 8), None);
    // Tight pack — slowest is still in-cluster
    let tight = [
        samp(0, 1_000_000, true),
        samp(1, 1_100_000, true),
        samp(2, 1_200_000, true),
        samp(3, 900_000, true),
        samp(4, 1_050_000, true),
        samp(5, 1_000_000, true),
        samp(6, 1_080_000, true),
        samp(7, 950_000, true),
    ];
    assert_eq!(relative_slow_pick(&tight, 8), None);

    // Mild spread, slowest > median/4 and median within 2× min
    let mild = [
        samp(0, 2_000_000, true),
        samp(1, 1_500_000, true),
        samp(2, 1_400_000, true),
        samp(3, 1_100_000, true),
        samp(4, 1_600_000, true),
        samp(5, 1_550_000, true),
        samp(6, 1_450_000, true),
        samp(7, 1_300_000, true),
    ];
    assert_eq!(relative_slow_pick(&mild, 8), None);

    // Half-median of a ~1.9 MB/s pack is kept (Gate B is quarter-median).
    let half = [
        samp(0, 2_000_000, true),
        samp(1, 1_900_000, true),
        samp(2, 1_800_000, true),
        samp(3, 800_000, true),
        samp(4, 1_850_000, true),
        samp(5, 1_950_000, true),
        samp(6, 1_880_000, true),
        samp(7, 1_920_000, true),
    ];
    assert_eq!(relative_slow_pick(&half, 8), None);

    // Clear quarter-median outlier
    let outlier = [
        samp(0, 2_000_000, true),
        samp(1, 1_900_000, true),
        samp(2, 1_800_000, true),
        samp(3, 400_000, true),
        samp(4, 1_850_000, true),
        samp(5, 1_950_000, true),
        samp(6, 1_880_000, true),
        samp(7, 1_920_000, true),
    ];
    assert_eq!(relative_slow_pick(&outlier, 8), Some(3));

    // One fast whale must not open Gate A on a home-speed pack.
    let whale = [
        samp(0, 1_400_000, true),
        samp(1, 2_000_000, true),
        samp(2, 2_200_000, true),
        samp(3, 2_400_000, true),
        samp(4, 2_500_000, true),
        samp(5, 2_600_000, true),
        samp(6, 2_700_000, true),
        samp(7, 14_000_000, true),
    ];
    assert_eq!(relative_slow_pick(&whale, 8), None);

    // Outlier without inflight is not kicked
    let no_work = [
        samp(0, 2_000_000, true),
        samp(1, 1_900_000, true),
        samp(2, 1_800_000, true),
        samp(3, 400_000, false),
        samp(4, 1_850_000, true),
        samp(5, 1_950_000, true),
        samp(6, 1_880_000, true),
        samp(7, 1_920_000, true),
    ];
    assert_eq!(relative_slow_pick(&no_work, 8), None);

    // Two outliers → worst (lowest bps)
    let two = [
        samp(0, 2_000_000, true),
        samp(1, 1_900_000, true),
        samp(2, 1_800_000, true),
        samp(3, 800_000, true),
        samp(4, 400_000, true),
        samp(5, 1_950_000, true),
        samp(6, 1_880_000, true),
        samp(7, 1_920_000, true),
    ];
    assert_eq!(relative_slow_pick(&two, 8), Some(4));
}

#[test]
fn relative_slow_hysteresis_is_wall_clock() {
    let outlier = [
        samp(0, 2_000_000, true),
        samp(1, 1_900_000, true),
        samp(2, 1_800_000, true),
        samp(3, 400_000, true),
        samp(4, 1_850_000, true),
        samp(5, 1_950_000, true),
        samp(6, 1_880_000, true),
        samp(7, 1_920_000, true),
    ];
    let (kick0, sus0) = relative_slow_with_hysteresis(&outlier, 8, 0, None, 0);
    assert_eq!(kick0, None);
    assert_eq!(sus0, Some((3, 0)));
    let (kick1, sus1) = relative_slow_with_hysteresis(&outlier, 8, 1_999, sus0, 0);
    assert_eq!(kick1, None);
    assert_eq!(sus1, Some((3, 0)));
    let (kick2, sus2) = relative_slow_with_hysteresis(&outlier, 8, 2_000, sus1, 0);
    assert_eq!(kick2, Some(3));
    assert_eq!(sus2, None);

    let tight = [
        samp(0, 1_000_000, true),
        samp(1, 1_100_000, true),
        samp(2, 1_200_000, true),
        samp(3, 900_000, true),
        samp(4, 1_050_000, true),
        samp(5, 1_000_000, true),
        samp(6, 1_080_000, true),
        samp(7, 950_000, true),
    ];
    let (kick3, sus3) = relative_slow_with_hysteresis(&tight, 8, 3_000, Some((3, 0)), 0);
    assert_eq!(kick3, None);
    assert!(sus3.is_none());

    let (kick4, sus4) =
        relative_slow_with_hysteresis(&outlier, 8, 12_000, Some((3, 10_000)), 10_000);
    assert_eq!(kick4, None, "5s kick gap not elapsed");
    assert_eq!(sus4, Some((3, 10_000)));
    let (kick5, sus5) = relative_slow_with_hysteresis(&outlier, 8, 15_000, sus4, 10_000);
    assert_eq!(kick5, Some(3));
    assert!(sus5.is_none());
}

#[test]
fn relative_slow_min_samples_scales() {
    assert_eq!(relative_slow_min_samples(16), 8);
    assert_eq!(relative_slow_min_samples(10), 6); // max(6, 5)=6
    assert_eq!(relative_slow_min_samples(4), 4); // min(alive)
    assert_eq!(relative_slow_min_samples(8), 6);
}

#[test]
fn apply_dial_result_updates_book() {
    let mut book = AddrMan::new();
    let good = addr(5);
    let bad = addr(6);
    let inc = addr(7);
    let slot = dummy_slot(0, good, true);
    let result = DialBatchResult {
        slots: vec![slot],
        failed: vec![
            (rbitcoin_net::NetAddr::Ip(bad), DialFailKind::Network),
            (rbitcoin_net::NetAddr::Ip(inc), DialFailKind::Incompatible),
        ],
        attempted: vec![
            rbitcoin_net::NetAddr::Ip(good),
            rbitcoin_net::NetAddr::Ip(bad),
            rbitcoin_net::NetAddr::Ip(inc),
        ],
    };
    let now = Instant::now();
    let mut cooldown = HashMap::new();
    let mut strikes = HashMap::new();
    apply_dial_result(&mut book, &result, &mut cooldown, &mut strikes, now);
    assert!(book.flags(&good).has_connected());
    assert!(book.flags(&bad).failed_last_connect());
    assert!(book.flags(&inc).is_incompatible());
    assert_eq!(
        cooldown
            .get(&rbitcoin_net::NetAddr::from_socket(bad))
            .copied(),
        Some(now + STALL_ADDR_COOLDOWN),
        "EOF/timeout enters the stall cooldown"
    );
    assert!(
        !cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(inc)),
        "incompatible is last-resort, not a stall ban"
    );
    apply_dial_result(&mut book, &result, &mut cooldown, &mut strikes, now);
    assert_eq!(
        cooldown
            .get(&rbitcoin_net::NetAddr::from_socket(bad))
            .copied(),
        Some(now + STALL_ADDR_COOLDOWN_2)
    );
    book.add(addr(8));
    let got = book.take_dial_candidates(8, &HashSet::new(), &[]);
    assert!(
        !got.contains(&good) && !got.contains(&bad) && !got.contains(&inc),
        "recently attempted addrs skipped while another remains: {got:?}"
    );
    assert_eq!(got, vec![addr(8)]);
}

#[test]
fn redial_want_at_least_two_when_short() {
    assert_eq!(redial_want(16, 16), 0);
    assert_eq!(redial_want(15, 16), 2);
    assert_eq!(redial_want(14, 16), 2);
    assert_eq!(redial_want(9, 16), 7);
    assert_eq!(redial_want(8, 16), 8);
    assert_eq!(redial_want(0, 16), 8);
    assert_eq!(redial_want(0, 1), 2);
}

#[test]
fn release_peer_block_work_clears_inflight() {
    let a = addr(9);
    let mut slot = dummy_slot(3, a, true);
    let h = BlockHash::from_byte_array([7u8; 32]);
    slot.in_flight.insert(h);
    let mut inflight = HashMap::new();
    inflight.insert(h, rbitcoin_ibd::ibd::state::InflightReq::new(3));
    let mut body = rbitcoin_ibd::ibd::body::BodyPresence::new();
    body.mark_pending(h);
    release_peer_block_work(&mut [slot], &mut inflight, &mut body, 3);
    assert!(inflight.is_empty());
    assert!(!body.is_pending(&h));
    assert!(body.is_missing(&h));
}

#[test]
fn release_peer_block_work_keeps_pending_for_another_owner() {
    let a = addr(9);
    let mut slot = dummy_slot(3, a, true);
    let h = BlockHash::from_byte_array([8u8; 32]);
    slot.in_flight.insert(h);
    let mut inflight = HashMap::new();
    let mut request = rbitcoin_ibd::ibd::state::InflightReq::new(3);
    request.add_peer(4);
    inflight.insert(h, request);
    let mut body = rbitcoin_ibd::ibd::body::BodyPresence::new();
    body.mark_pending(h);

    release_peer_block_work(&mut [slot], &mut inflight, &mut body, 3);

    assert!(inflight.contains_key(&h));
    assert!(body.is_pending(&h));
    assert!(!body.is_missing(&h));
}

#[test]
fn release_peer_block_work_returns_hashes_left_unrequested() {
    let mut slot = dummy_slot(3, addr(9), true);
    let sole = BlockHash::from_byte_array([7u8; 32]);
    let shared = BlockHash::from_byte_array([8u8; 32]);
    slot.in_flight.insert(sole);
    slot.in_flight.insert(shared);
    let mut inflight = HashMap::new();
    inflight.insert(sole, rbitcoin_ibd::ibd::state::InflightReq::new(3));
    let mut both = rbitcoin_ibd::ibd::state::InflightReq::new(3);
    both.add_peer(4);
    inflight.insert(shared, both);
    let mut body = rbitcoin_ibd::ibd::body::BodyPresence::new();
    let freed = release_peer_block_work(&mut [slot], &mut inflight, &mut body, 3);
    assert_eq!(
        freed,
        vec![sole],
        "a hash another peer still holds stays requested"
    );
    assert!(inflight.contains_key(&shared));
}

#[test]
fn dial_batch_empty_count_or_book() {
    let book = AddrMan::new();
    let (body_tx, _body_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ctrl_tx, _ctrl_rx) = tokio::sync::mpsc::unbounded_channel();
    let sinks = PeerEventSinks {
        body: body_tx,
        ctrl: ctrl_tx,

        header_fks: rbitcoin_ibd::ibd::peer_io::empty_header_fk_bus(),
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let r = rt.block_on(dial_batch(
        &book,
        0,
        HashSet::new(),
        &[],
        Magic::REGTEST,
        addr(1),
        Some(0),
        sinks.clone(),
        Duration::from_millis(50),
        None,
        rbitcoin_net::socks::Dialer::Direct,
        &rbitcoin_consensus::NodeClock::new(),
        None,
    ));
    assert!(r.slots.is_empty() && r.failed.is_empty());
    let r2 = rt.block_on(dial_batch(
        &book,
        4,
        HashSet::new(),
        &[],
        Magic::REGTEST,
        addr(1),
        None,
        sinks,
        Duration::from_millis(50),
        None,
        rbitcoin_net::socks::Dialer::Direct,
        &rbitcoin_consensus::NodeClock::new(),
        None,
    ));
    assert!(r2.slots.is_empty() && r2.failed.is_empty());
}

/// IBD dials do not go through `prepare_outbound_session`.
#[tokio::test]
async fn ibd_dial_refuses_a_discouraged_net() {
    let peers = rbitcoin_net::peers::PeerHub::new(rbitcoin_consensus::NodeClock::new());
    peers.clock.set_mock(1_700_000_000_i64);
    peers.on_clock_jump();
    let onion = rbitcoin_net::NetAddr::Onion {
        pk: [4; 32],
        port: 8333,
    };
    peers.note_misbehavior_key(rbitcoin_net::peers::DiscourageKey::from_net(onion).unwrap());
    let other_port = rbitcoin_net::NetAddr::Onion {
        pk: [4; 32],
        port: 9735,
    };
    let (body_tx, _body_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ctrl_tx, _ctrl_rx) = tokio::sync::mpsc::unbounded_channel();
    let sinks = PeerEventSinks {
        body: body_tx,
        ctrl: ctrl_tx,
        header_fks: rbitcoin_ibd::ibd::peer_io::empty_header_fk_bus(),
    };
    let result = tokio::time::timeout(
        Duration::from_millis(200),
        rbitcoin_ibd::ibd::peer_io::spawn_peer(
            1,
            other_port,
            Magic::REGTEST,
            addr(1),
            Some(0),
            sinks,
            rbitcoin_net::socks::Dialer::Direct,
            Some(peers),
        ),
    )
    .await;
    let err = match result.expect("a refused IBD dial returns before the connect") {
        Err(e) => e,
        Ok(_) => panic!("IBD dial connected to a discouraged onion"),
    };
    assert!(
        matches!(err, NetError::Protocol("discouraged")),
        "IBD dialed a discouraged onion on another port, got {err}"
    );
}

#[test]
fn alive_dial_addrs_skips_dead() {
    let a = addr(1);
    let b = addr(2);
    let slots = vec![dummy_slot(1, a, true), dummy_slot(2, b, false)];
    assert_eq!(alive_dial_addrs(&slots), vec![a]);
}

#[test]
fn disconnect_stalled_after_30s_without_rx() {
    let a = addr(11);
    let mut slot = dummy_slot(5, a, true);
    let h = BlockHash::from_byte_array([0xee; 32]);
    slot.in_flight.insert(h);
    slot.rate.note_work_started(0);
    let mut inflight = HashMap::new();
    inflight.insert(h, rbitcoin_ibd::ibd::state::InflightReq::new(5));
    let mut cooldown = HashMap::new();
    let mut strikes = HashMap::new();
    rbitcoin_net::chain::reset_header_store_counts();
    disconnect_stalled_block_peers_at(
        std::slice::from_mut(&mut slot),
        &mut inflight,
        &mut rbitcoin_ibd::ibd::body::BodyPresence::new(),
        &mut cooldown,
        &mut strikes,
        Instant::now(),
        Duration::from_secs(30),
        30_001,
    );
    assert!(cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(a)));
    assert!(inflight.is_empty());
    assert_eq!(rbitcoin_net::chain::header_store_counts(), (0, 0, 0));
}

#[test]
fn disconnect_stalled_not_when_rx_recent() {
    let a = addr(12);
    let mut slot = dummy_slot(6, a, true);
    let h = BlockHash::from_byte_array([0xee; 32]);
    slot.in_flight.insert(h);
    slot.rate.note_work_started(0);
    slot.rate.note_rx(25_000);
    let mut inflight = HashMap::new();
    inflight.insert(h, rbitcoin_ibd::ibd::state::InflightReq::new(6));
    let mut cooldown = HashMap::new();
    let mut strikes = HashMap::new();
    disconnect_stalled_block_peers_at(
        std::slice::from_mut(&mut slot),
        &mut inflight,
        &mut rbitcoin_ibd::ibd::body::BodyPresence::new(),
        &mut cooldown,
        &mut strikes,
        Instant::now(),
        Duration::from_secs(30),
        45_000,
    );
    assert!(!cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(a)));
    assert!(inflight.contains_key(&h));
}

fn hash_byte(b: u8) -> BlockHash {
    BlockHash::from_byte_array([b; 32])
}

/// One requested hash is on the wire as of `written_ms`.
fn put_on_wire(slot: &mut PeerSlot, hash: BlockHash, written_ms: u64) {
    slot.in_flight.insert(hash);
    slot.getdata_wire.queue(1);
    slot.getdata_wire.wrote(1, written_ms);
}

/// Idle time before a window does not count. The opening write starts
/// 30s. A later write while that hash is still out does not.
#[test]
fn disconnect_stalled_opening_write_starts_a_fresh_window() {
    let a = addr(14);
    let mut slot = dummy_slot(8, a, true);
    let h = hash_byte(0x14);
    put_on_wire(&mut slot, h, 40_000);
    slot.rate.note_rx(0);
    let mut inflight = HashMap::new();
    inflight.insert(h, rbitcoin_ibd::ibd::state::InflightReq::new(8));
    let mut cooldown = HashMap::new();
    let mut strikes = HashMap::new();
    disconnect_stalled_block_peers_at(
        std::slice::from_mut(&mut slot),
        &mut inflight,
        &mut rbitcoin_ibd::ibd::body::BodyPresence::new(),
        &mut cooldown,
        &mut strikes,
        Instant::now(),
        Duration::from_secs(30),
        50_000,
    );
    assert!(
        !cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(a)),
        "10s after the opening write is inside the new window"
    );
    assert!(inflight.contains_key(&h));

    let later = hash_byte(0x15);
    put_on_wire(&mut slot, later, 55_000);
    inflight.insert(later, rbitcoin_ibd::ibd::state::InflightReq::new(8));
    disconnect_stalled_block_peers_at(
        std::slice::from_mut(&mut slot),
        &mut inflight,
        &mut rbitcoin_ibd::ibd::body::BodyPresence::new(),
        &mut cooldown,
        &mut strikes,
        Instant::now(),
        Duration::from_secs(30),
        70_001,
    );
    assert!(
        cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(a)),
        "the second write must not move the window off t=40s"
    );
    assert!(inflight.is_empty());
}

/// Draining the last outstanding hash disarms the clock. The next write
/// starts 30s even when the last block is ancient.
#[test]
fn disconnect_stalled_rearms_after_the_window_drains() {
    let a = addr(28);
    let mut slot = dummy_slot(21, a, true);
    let h = hash_byte(0x28);
    put_on_wire(&mut slot, h, 0);
    slot.rate.note_rx(0);
    assert!(slot.track_remove(&h));
    assert!(slot.in_flight.is_empty());

    let next = hash_byte(0x29);
    put_on_wire(&mut slot, next, 100_000);
    slot.rate.note_rx(0);
    let mut inflight = HashMap::new();
    inflight.insert(next, rbitcoin_ibd::ibd::state::InflightReq::new(21));
    let mut cooldown = HashMap::new();
    let mut strikes = HashMap::new();
    disconnect_stalled_block_peers_at(
        std::slice::from_mut(&mut slot),
        &mut inflight,
        &mut rbitcoin_ibd::ibd::body::BodyPresence::new(),
        &mut cooldown,
        &mut strikes,
        Instant::now(),
        Duration::from_secs(30),
        110_000,
    );
    assert!(
        !cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(a)),
        "a drained window does not keep the old deadline"
    );
    disconnect_stalled_block_peers_at(
        std::slice::from_mut(&mut slot),
        &mut inflight,
        &mut rbitcoin_ibd::ibd::body::BodyPresence::new(),
        &mut cooldown,
        &mut strikes,
        Instant::now(),
        Duration::from_secs(30),
        130_001,
    );
    assert!(cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(a)));
    assert!(inflight.is_empty());
}

#[test]
fn disconnect_stalled_skips_getdata_still_in_the_writer() {
    let a = addr(15);
    let mut slot = dummy_slot(9, a, true);
    let h = hash_byte(0x15);
    slot.in_flight.insert(h);
    slot.getdata_wire.queue(1);
    slot.rate.note_rx(0);
    let mut inflight = HashMap::new();
    inflight.insert(h, rbitcoin_ibd::ibd::state::InflightReq::new(9));
    let mut cooldown = HashMap::new();
    let mut strikes = HashMap::new();
    disconnect_stalled_block_peers_at(
        std::slice::from_mut(&mut slot),
        &mut inflight,
        &mut rbitcoin_ibd::ibd::body::BodyPresence::new(),
        &mut cooldown,
        &mut strikes,
        Instant::now(),
        Duration::from_secs(30),
        90_000,
    );
    assert!(!cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(a)));
    assert!(inflight.contains_key(&h));
}

#[test]
fn disconnect_stalled_drops_one_when_every_peer_is_quiet() {
    let a = addr(16);
    let b = addr(17);
    let mut sa = dummy_slot(10, a, true);
    let mut sb = dummy_slot(11, b, true);
    let ha = hash_byte(0x16);
    let hb = hash_byte(0x17);
    put_on_wire(&mut sa, ha, 0);
    put_on_wire(&mut sb, hb, 0);
    sa.rate.note_rx(0);
    sb.rate.note_rx(0);
    let mut inflight = HashMap::new();
    inflight.insert(ha, rbitcoin_ibd::ibd::state::InflightReq::new(10));
    inflight.insert(hb, rbitcoin_ibd::ibd::state::InflightReq::new(11));
    let mut cooldown = HashMap::new();
    let mut strikes = HashMap::new();
    disconnect_stalled_block_peers_at(
        &mut [sa, sb],
        &mut inflight,
        &mut rbitcoin_ibd::ibd::body::BodyPresence::new(),
        &mut cooldown,
        &mut strikes,
        Instant::now(),
        Duration::from_secs(30),
        60_000,
    );
    assert_eq!(
        cooldown.len(),
        1,
        "one quiet peer per pass, so give-up stays reachable"
    );
    assert_eq!(inflight.len(), 1);
    assert!(
        cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(a))
            ^ cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(b))
    );
}

#[test]
fn disconnect_stalled_ignores_silence_without_getdata() {
    let idle_addr = addr(21);
    let quiet_addr = addr(22);
    let mut idle = dummy_slot(14, idle_addr, true);
    let mut quiet = dummy_slot(15, quiet_addr, true);
    let hq = hash_byte(0x22);
    put_on_wire(&mut quiet, hq, 0);
    idle.rate.note_rx(0);
    quiet.rate.note_rx(0);
    let mut inflight = HashMap::new();
    inflight.insert(hq, rbitcoin_ibd::ibd::state::InflightReq::new(15));
    let mut cooldown = HashMap::new();
    let mut strikes = HashMap::new();
    disconnect_stalled_block_peers_at(
        &mut [idle, quiet],
        &mut inflight,
        &mut rbitcoin_ibd::ibd::body::BodyPresence::new(),
        &mut cooldown,
        &mut strikes,
        Instant::now(),
        Duration::from_secs(30),
        60_000,
    );
    assert!(
        !cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(idle_addr)),
        "no assigned getdata is not a quiet peer"
    );
    assert!(cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(quiet_addr)));
    assert!(inflight.is_empty());
}

#[test]
fn disconnect_stalled_drops_only_the_quiet_peer() {
    let quiet_addr = addr(18);
    let live_addr = addr(19);
    let mut quiet = dummy_slot(12, quiet_addr, true);
    let mut live = dummy_slot(13, live_addr, true);
    let hq = hash_byte(0x18);
    let hl = hash_byte(0x19);
    put_on_wire(&mut quiet, hq, 0);
    put_on_wire(&mut live, hl, 0);
    quiet.rate.note_rx(0);
    live.rate.note_rx(50_000);
    let mut inflight = HashMap::new();
    inflight.insert(hq, rbitcoin_ibd::ibd::state::InflightReq::new(12));
    inflight.insert(hl, rbitcoin_ibd::ibd::state::InflightReq::new(13));
    let mut cooldown = HashMap::new();
    let mut strikes = HashMap::new();
    disconnect_stalled_block_peers_at(
        &mut [quiet, live],
        &mut inflight,
        &mut rbitcoin_ibd::ibd::body::BodyPresence::new(),
        &mut cooldown,
        &mut strikes,
        Instant::now(),
        Duration::from_secs(30),
        60_000,
    );
    assert!(cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(quiet_addr)));
    assert!(!cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(live_addr)));
    assert!(!inflight.contains_key(&hq));
    assert!(inflight.contains_key(&hl));
}

#[test]
fn disconnect_stalled_drops_one_when_every_peer_chats_without_blocks() {
    let a = addr(23);
    let b = addr(24);
    let mut sa = dummy_slot(16, a, true);
    let mut sb = dummy_slot(17, b, true);
    let ha = hash_byte(0x23);
    let hb = hash_byte(0x24);
    put_on_wire(&mut sa, ha, 0);
    put_on_wire(&mut sb, hb, 0);
    sa.rate.note_rx(0);
    sb.rate.note_rx(0);
    sa.rate.note_any_rx(50_000);
    sb.rate.note_any_rx(50_000);
    sa.bytes_rx_total.store(100, Ordering::Relaxed);
    sb.bytes_rx_total.store(100, Ordering::Relaxed);
    let mut inflight = HashMap::new();
    inflight.insert(ha, rbitcoin_ibd::ibd::state::InflightReq::new(16));
    inflight.insert(hb, rbitcoin_ibd::ibd::state::InflightReq::new(17));
    let mut cooldown = HashMap::new();
    let mut strikes = HashMap::new();
    disconnect_stalled_block_peers_at(
        &mut [sa, sb],
        &mut inflight,
        &mut rbitcoin_ibd::ibd::body::BodyPresence::new(),
        &mut cooldown,
        &mut strikes,
        Instant::now(),
        Duration::from_secs(30),
        60_000,
    );
    assert_eq!(cooldown.len(), 1);
    assert_eq!(inflight.len(), 1);
}

#[test]
fn disconnect_stalled_keeps_a_chatter_beside_a_block_sender() {
    let chat_addr = addr(25);
    let live_addr = addr(26);
    let mut chat = dummy_slot(18, chat_addr, true);
    let mut live = dummy_slot(19, live_addr, true);
    let hc = hash_byte(0x25);
    let hl = hash_byte(0x26);
    put_on_wire(&mut chat, hc, 0);
    put_on_wire(&mut live, hl, 0);
    chat.rate.note_rx(0);
    chat.rate.note_any_rx(50_000);
    chat.bytes_rx_total.store(80, Ordering::Relaxed);
    live.rate.note_rx(50_000);
    let mut inflight = HashMap::new();
    inflight.insert(hc, rbitcoin_ibd::ibd::state::InflightReq::new(18));
    inflight.insert(hl, rbitcoin_ibd::ibd::state::InflightReq::new(19));
    let mut cooldown = HashMap::new();
    let mut strikes = HashMap::new();
    disconnect_stalled_block_peers_at(
        &mut [chat, live],
        &mut inflight,
        &mut rbitcoin_ibd::ibd::body::BodyPresence::new(),
        &mut cooldown,
        &mut strikes,
        Instant::now(),
        Duration::from_secs(30),
        60_000,
    );
    assert!(cooldown.is_empty());
    assert_eq!(inflight.len(), 2);
}

#[test]
fn disconnect_stalled_keeps_a_peer_still_sending_a_block() {
    let a = addr(27);
    let mut slot = dummy_slot(20, a, true);
    let h = hash_byte(0x27);
    put_on_wire(&mut slot, h, 0);
    slot.rate.note_rx(0);
    slot.rate.note_any_rx(50_000);
    slot.bytes_rx_total
        .store(rbitcoin_ibd::ibd::rate::PROGRESS_STEP, Ordering::Relaxed);
    let mut inflight = HashMap::new();
    inflight.insert(h, rbitcoin_ibd::ibd::state::InflightReq::new(20));
    let mut cooldown = HashMap::new();
    let mut strikes = HashMap::new();
    disconnect_stalled_block_peers_at(
        std::slice::from_mut(&mut slot),
        &mut inflight,
        &mut rbitcoin_ibd::ibd::body::BodyPresence::new(),
        &mut cooldown,
        &mut strikes,
        Instant::now(),
        Duration::from_secs(30),
        60_000,
    );
    assert!(cooldown.is_empty());
    assert!(inflight.contains_key(&h));
}

#[test]
fn disconnect_stalled_releases_and_cools_addr() {
    let now = Instant::now();
    let mut cooldown = HashMap::new();
    let mut strikes = HashMap::new();
    disconnect_stalled_block_peers(
        &mut [dummy_slot(7, addr(13), true)],
        &mut HashMap::new(),
        &mut rbitcoin_ibd::ibd::body::BodyPresence::new(),
        &mut cooldown,
        &mut strikes,
        now,
        Duration::from_secs(30),
    );
    assert!(!cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(addr(13))));
}

#[test]
fn request_headers_no_alive_returns_false() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("dial-hdr");
    let mut seq = 0u32;
    let mut dead = dummy_slot(1, addr(1), false);
    dead.alive = false;
    assert!(!request_headers_from(&[dead], 1, &mut seq, vec![]).unwrap());
    // Locator alone (empty work tips + no tip) still returns genesis zero.
    let loc = ibd_header_locator(&hub, &[], &[]);
    assert!(!loc.is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

/// median / pick edge matrix + mature-sample early exits + relative-slow early exits.
#[test]
fn relative_slow_pure_edges_and_mature_sample_filters() {
    assert_eq!(median_u64(&[]), 0);
    assert_eq!(median_u64(&[7]), 7);
    assert_eq!(median_u64(&[2, 8]), 5);
    assert_eq!(median_u64(&[1, 2, 3]), 2);
    assert_eq!(relative_slow_min_samples(0), RELATIVE_SLOW_MIN_SAMPLES);

    // All-zero bps → none (the stall pass owns a set with no block bytes).
    let zeros: Vec<_> = (0..8).map(|i| samp(i, 0, true)).collect();
    assert_eq!(relative_slow_pick(&zeros, 8), None);
    // A peer with inflight work and no block bytes is the outlier.
    let zero_and_fast = [
        samp(0, 0, true),
        samp(1, 2_000_000, true),
        samp(2, 1_900_000, true),
        samp(3, 1_800_000, true),
        samp(4, 1_850_000, true),
        samp(5, 1_950_000, true),
        samp(6, 1_880_000, true),
        samp(7, 1_920_000, true),
    ];
    assert_eq!(relative_slow_pick(&zero_and_fast, 8), Some(0));

    // Equal worst bps → lower peer_id wins.
    let tie = [
        samp(5, 400_000, true),
        samp(2, 400_000, true),
        samp(0, 2_000_000, true),
        samp(1, 1_900_000, true),
        samp(3, 1_800_000, true),
        samp(4, 1_850_000, true),
        samp(6, 1_880_000, true),
        samp(7, 1_920_000, true),
    ];
    assert_eq!(relative_slow_pick(&tie, 8), Some(2));

    // Mature filters: dead / young active_ms / no sample.
    let dead = {
        let mut s = dummy_slot(0, addr(20), false);
        s.rate.sample(0, 0, true);
        s.rate
            .sample(RELSLOW_ACTIVE_MS, RELSLOW_ACTIVE_MS * 1_000, true);
        s
    };
    let young = {
        let mut s = dummy_slot(2, addr(22), true);
        s.rate.sample(0, 0, true);
        s.rate.sample(5_000, 50_000_000, true);
        s
    };
    let samples = mature_relative_slow_samples(&[dead, young], RELSLOW_ACTIVE_MS);
    assert!(samples.iter().all(|s| s.peer_id != 0 && s.peer_id != 2));

    assert_eq!(global_first_block_ms(&[]), 0);
    let a_empty = dummy_slot(10, addr(30), true);
    assert_eq!(global_first_block_ms(std::slice::from_ref(&a_empty)), 0);
    let b_dead = {
        let mut s = dummy_slot(11, addr(31), true);
        s.alive = false;
        s.first_data_ms = 5;
        s
    };
    assert_eq!(global_first_block_ms(std::slice::from_ref(&b_dead)), 0);
    let a = {
        let mut s = dummy_slot(10, addr(30), true);
        s.first_data_ms = 42;
        s
    };
    let c = {
        let mut s = dummy_slot(12, addr(32), true);
        s.first_data_ms = 10;
        s
    };
    assert_eq!(global_first_block_ms(&[a, c]), 10);
    // Warmup fails when age since global first < 60s (typical unit-test process).
    let a2 = {
        let mut s = dummy_slot(10, addr(30), true);
        s.first_data_ms = 10;
        s
    };
    let warm = relative_slow_global_warmup_at(std::slice::from_ref(&a2), ibd_mono_ms());
    if ibd_mono_ms().saturating_sub(10) < RELATIVE_SLOW_GLOBAL_WARMUP_MS {
        assert!(!warm);
    }

    // disconnect_relative_slow: fail warmup → clear suspect; thin samples → clear.
    let mut slots = [dummy_slot(1, addr(40), true)];
    let mut inflight = HashMap::new();
    let mut cooldown = HashMap::new();
    let mut strikes = HashMap::new();
    let mut suspect = Some((1usize, 0u64));
    let mut last_kick_ms = 0u64;
    let mut book = AddrMan::new();
    book.add(addr(41));
    book.note_connect_failed_addr(rbitcoin_net::NetAddr::from_socket(addr(41)), false);
    let now = Instant::now();
    assert!(
        !replacement_available(&book, &slots, &cooldown, now),
        "a failed last connect is not a replacement"
    );
    book.add(addr(42));
    assert!(
        replacement_available(&book, &slots, &cooldown, now),
        "an untried address can replace a kicked peer"
    );
    cooldown.insert(
        rbitcoin_net::NetAddr::from_socket(addr(42)),
        now + Duration::from_secs(60),
    );
    assert!(
        !replacement_available(&book, &slots, &cooldown, now),
        "cooling the only clean address leaves no replacement"
    );
    cooldown.clear();
    disconnect_relative_slow_block_peers(
        &mut slots,
        &mut inflight,
        &mut rbitcoin_ibd::ibd::body::BodyPresence::new(),
        &mut cooldown,
        &mut strikes,
        now,
        &book,
        &mut suspect,
        &mut last_kick_ms,
    );
    assert!(suspect.is_none());
    assert!(cooldown.is_empty());
    relative_slow_kick_needs_a_replacement();
}

/// Same journey: expiry at `now`, a live address, and a post-warmup kick.
fn relative_slow_kick_needs_a_replacement() {
    let now = Instant::now();
    let mut book = AddrMan::new();
    book.add(addr(41));
    book.note_connect_failed_addr(rbitcoin_net::NetAddr::from_socket(addr(41)), false);
    book.add(addr(42));
    let mut cooldown = HashMap::new();
    cooldown.insert(rbitcoin_net::NetAddr::from_socket(addr(42)), now);
    let idle = [dummy_slot(1, addr(40), true)];
    assert!(
        replacement_available(&book, &idle, &cooldown, now),
        "a cooldown that ends at now is not still cooling"
    );
    let live_peer = dummy_slot(7, addr(42), true);
    assert!(
        !replacement_available(
            &book,
            std::slice::from_ref(&live_peer),
            &HashMap::new(),
            now
        ),
        "the live peer is not its own replacement"
    );

    let h = BlockHash::from_byte_array([0x71; 32]);
    let mut pack = Vec::new();
    for i in 0..8 {
        let mut s = dummy_slot(i, addr(60 + i as u8), true);
        s.first_data_ms = 1_000;
        s.rate.sample(0, 0, true);
        let bytes = if i == 0 { 4_500_000 } else { 45_000_000 };
        s.rate.sample(RELSLOW_ACTIVE_MS, bytes, true);
        s.in_flight.insert(h);
        pack.push(s);
    }
    let slow_addr = addr(60);
    let mut kicked_book = AddrMan::new();
    kicked_book.add(addr(80));
    kicked_book.note_connect_failed_addr(rbitcoin_net::NetAddr::from_socket(addr(80)), false);
    cooldown.clear();
    let t_warm = 1_000 + RELATIVE_SLOW_GLOBAL_WARMUP_MS;
    let mut inflight = HashMap::new();
    let mut strikes = HashMap::new();
    let mut suspect = None;
    let mut last_kick_ms = 0u64;
    let mut body = rbitcoin_ibd::ibd::body::BodyPresence::new();
    disconnect_relative_slow_block_peers_at(
        &mut pack,
        &mut inflight,
        &mut body,
        &mut cooldown,
        &mut strikes,
        now,
        &kicked_book,
        &mut suspect,
        &mut last_kick_ms,
        t_warm,
    );
    disconnect_relative_slow_block_peers_at(
        &mut pack,
        &mut inflight,
        &mut body,
        &mut cooldown,
        &mut strikes,
        now,
        &kicked_book,
        &mut suspect,
        &mut last_kick_ms,
        t_warm + RELATIVE_SLOW_HYSTERESIS_MS,
    );
    assert!(
        !cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(slow_addr)),
        "no clean address outside cooldown, so the outlier stays"
    );
    kicked_book.add(addr(81));
    suspect = None;
    last_kick_ms = 0;
    disconnect_relative_slow_block_peers_at(
        &mut pack,
        &mut inflight,
        &mut body,
        &mut cooldown,
        &mut strikes,
        now,
        &kicked_book,
        &mut suspect,
        &mut last_kick_ms,
        t_warm,
    );
    assert_eq!(suspect.map(|s| s.0), Some(0));
    disconnect_relative_slow_block_peers_at(
        &mut pack,
        &mut inflight,
        &mut body,
        &mut cooldown,
        &mut strikes,
        now,
        &kicked_book,
        &mut suspect,
        &mut last_kick_ms,
        t_warm + RELATIVE_SLOW_HYSTERESIS_MS,
    );
    assert!(
        cooldown.contains_key(&rbitcoin_net::NetAddr::from_socket(slow_addr)),
        "an untried replacement allows the relative-slow kick"
    );
}

#[test]
fn mature_relative_slow_samples_uses_ewma_active_ms() {
    let h = BlockHash::from_byte_array([9u8; 32]);
    let mut young = dummy_slot(0, addr(50), true);
    young.rate.sample(0, 0, true);
    young.rate.sample(5_000, 50_000_000, true);
    young.in_flight.insert(h);
    assert!(young.rate.bps().is_some());
    assert!(young.rate.active_ms < RELSLOW_ACTIVE_MS);

    let mut mature = dummy_slot(1, addr(51), true);
    mature.rate.sample(0, 0, true);
    mature
        .rate
        .sample(RELSLOW_ACTIVE_MS, RELSLOW_ACTIVE_MS * 10_000, true);
    mature.in_flight.insert(h);

    let samples = mature_relative_slow_samples(&[young, mature], RELSLOW_ACTIVE_MS);
    assert!(samples.iter().all(|s| s.peer_id != 0));
    assert!(samples.iter().any(|s| s.peer_id == 1));
}

/// Frozen high EWMAs from peers that stopped sending must not make a
/// peer that just delivered the relative-slow outlier.
#[test]
fn stale_high_rates_do_not_evict_a_peer_that_just_sent() {
    let now = 90_000u64;
    let quiet_at = 30_000u64;
    let h = BlockHash::from_byte_array([0x61; 32]);
    let mut slots = Vec::new();
    for i in 0..6u8 {
        let mut s = dummy_slot(i as usize, addr(i), true);
        s.rate.sample(0, 0, true);
        // ~1 MB/s EWMA, last rx 60s ago, nothing in flight.
        s.rate.sample(quiet_at, 45_000_000, true);
        s.rate.note_rx(quiet_at);
        slots.push(s);
    }
    for i in 6..12u8 {
        let mut s = dummy_slot(i as usize, addr(i), true);
        s.rate.sample(0, 0, true);
        // ~100 KB/s, bytes just arrived, still holding getdata.
        s.rate.sample(quiet_at, 4_500_000, true);
        s.rate.note_rx(now);
        s.in_flight.insert(h);
        slots.push(s);
    }
    let samples = mature_relative_slow_samples(&slots, now);
    let pick = relative_slow_pick(&samples, relative_slow_min_samples(slots.len()));
    assert_eq!(pick, None, "samples={samples:?}");
}

#[test]
fn kick_cooldown_escalates_on_repeat_strikes() {
    assert_eq!(kick_cooldown_for(0), STALL_ADDR_COOLDOWN);
    assert_eq!(kick_cooldown_for(1), STALL_ADDR_COOLDOWN);
    assert_eq!(kick_cooldown_for(2), STALL_ADDR_COOLDOWN_2);
    assert_eq!(kick_cooldown_for(3), STALL_ADDR_COOLDOWN_3);
    assert_eq!(kick_cooldown_for(9), STALL_ADDR_COOLDOWN_3);

    let a = rbitcoin_net::NetAddr::from_socket(addr(70));
    let t0 = Instant::now();
    let mut cooldown = HashMap::new();
    let mut strikes = HashMap::new();
    let d1 = record_stall_kick(&mut cooldown, &mut strikes, a, t0);
    assert_eq!(d1, STALL_ADDR_COOLDOWN);
    assert_eq!(cooldown.get(&a).copied(), Some(t0 + STALL_ADDR_COOLDOWN));
    let d2 = record_stall_kick(&mut cooldown, &mut strikes, a, t0);
    assert_eq!(d2, STALL_ADDR_COOLDOWN_2);
    let until2 = cooldown.get(&a).copied().unwrap();
    assert_eq!(until2, t0 + STALL_ADDR_COOLDOWN_2);
    assert!(until2 > t0 + STALL_ADDR_COOLDOWN);
    let d3 = record_stall_kick(&mut cooldown, &mut strikes, a, t0);
    assert_eq!(d3, STALL_ADDR_COOLDOWN_3);
    expire_addr_cooldown(
        &mut cooldown,
        &mut strikes,
        &AddrMan::new(),
        t0 + STALL_ADDR_COOLDOWN + Duration::from_secs(1),
    );
    assert!(
        cooldown.contains_key(&a),
        "second-kick 30m ban still holds after 10m+1s"
    );
    expire_addr_cooldown(
        &mut cooldown,
        &mut strikes,
        &AddrMan::new(),
        t0 + STALL_ADDR_COOLDOWN_2 + Duration::from_secs(1),
    );
    assert!(
        cooldown.contains_key(&a),
        "third-kick 2h ban still holds after 30m+1s"
    );
    expire_addr_cooldown(
        &mut cooldown,
        &mut strikes,
        &AddrMan::new(),
        t0 + STALL_ADDR_COOLDOWN_3 + Duration::from_secs(1),
    );
    assert!(!cooldown.contains_key(&a));
}
