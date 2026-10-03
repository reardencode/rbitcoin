use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_network::VersionMessage;
use std::net::Ipv6Addr;

const ONION: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333";

fn onion_addr() -> crate::NetAddr {
    ONION.parse().unwrap()
}

fn dial_targets_roundtrip() {
    let onion = onion_addr();
    let t = DialTarget::from_net(onion);
    assert!(matches!(t, DialTarget::Domain { .. }), "{t:?}");
    assert_eq!(t.net_addr(), onion);
    let hint = t.version_socket();
    assert!(hint.ip().is_unspecified(), "{hint}");
    assert_eq!(hint.port(), 8333);

    let ip = Ipv6Addr::new(0xfc00, 1, 2, 3, 4, 5, 6, 7);
    let cjdns = crate::NetAddr::Cjdns { ip, port: 8333 };
    assert_eq!(
        DialTarget::from_net(cjdns),
        DialTarget::Socket(SocketAddr::from((ip, 8333)))
    );
    assert_eq!(DialTarget::from_net(cjdns).net_addr(), cjdns);

    let i2p = crate::NetAddr::I2p {
        dest: [7u8; 32],
        port: 8333,
    };
    let t = DialTarget::from_net(i2p);
    assert!(matches!(t, DialTarget::Domain { .. }), "{t:?}");
    assert_eq!(t.net_addr(), i2p);
}

fn learn_overlay(hub: &Arc<PeerHub>, addr: AddrV2, port: u16, time: u32) {
    hub.learn_addrv2(&[AddrV2Message {
        time,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::P2P_V2,
        addr,
        port,
    }]);
}

fn book_has(am: &Mutex<crate::seeds::AddrMan>, want: crate::NetAddr) -> bool {
    am.lock()
        .unwrap_or_else(|e| e.into_inner())
        .entries()
        .iter()
        .any(|e| e.addr == want)
}

fn inbound_fc00_is_cjdns(hub: &Arc<PeerHub>) {
    let ip = Ipv6Addr::new(0xfc00, 1, 2, 3, 4, 5, 6, 7);
    let addr = SocketAddr::from((ip, 8333));
    let bind = SocketAddr::from((ip, 18444));
    let connecting = hub.register_connecting(addr, bind, true, PeerConnType::Inbound);
    assert_eq!(connecting.net.network_label(), "cjdns");
    hub.unregister(connecting.id);
    let ver = VersionMessage {
        version: bitcoin::p2p::PROTOCOL_VERSION,
        services: ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&bind, ServiceFlags::NONE),
        nonce: 0,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 3,
        relay: true,
    };
    let live = hub.register_with_id(1, addr, bind, &ver, true, PeerConnType::Inbound);
    assert_eq!(live.net.network_label(), "cjdns");
    assert_eq!(hub.snapshot()[0].net.network_label(), "cjdns");
}

fn advertise_then_self_announce(hub: &Arc<PeerHub>) {
    let ip = Ipv6Addr::new(0xfc00, 1, 2, 3, 4, 5, 6, 7);
    hub.set_discover(true);
    hub.set_clearnet_listen(true);
    hub.set_listen_port(8333);
    hub.set_external_ips(vec![IpAddr::V6(ip)]);
    assert!(hub.advertise_local_socket().is_none());
    hub.set_cjdns_reachable(true);
    let sock = hub.advertise_local_socket().expect("cjdns listen");
    assert_eq!(sock.ip(), IpAddr::V6(ip));
    assert_eq!(sock.port(), 8333);

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let v1_peer = hub.register(addr, addr, &ver, false, PeerConnType::OutboundFullRelay);
    assert!(
        v1_peer.take_self_announce_msg().is_none(),
        "v1 ADDR must not re-encode CJDNS as IPv6"
    );
    let v2_peer = hub.register(addr, addr, &ver, false, PeerConnType::OutboundFullRelay);
    v2_peer.set_wants_addrv2();
    match v2_peer.take_self_announce_msg().expect("cjdns addrv2") {
        NetworkMessage::AddrV2(v) => {
            assert_eq!(v.len(), 1, "{v:?}");
            assert!(matches!(v[0].addr, AddrV2::Cjdns(_)), "{v:?}");
            assert_eq!(v[0].port, 8333);
        }
        other => panic!("expected AddrV2 CJDNS, got {other:?}"),
    }
}

fn only_net_dials_and_peers_file(am: &Mutex<crate::seeds::AddrMan>, overlays: [crate::NetAddr; 3]) {
    use crate::netaddr::OnlyNet;
    let [onion, i2p, cjdns] = overlays;
    let crate::NetAddr::Cjdns { ip, port } = cjdns else {
        panic!("{cjdns}");
    };
    let cjdns_sock = SocketAddr::from((ip, port));
    let book = am.lock().unwrap_or_else(|e| e.into_inner()).clone();

    let clear = book.take_dial_candidates(8, &HashSet::new(), &[]);
    assert!(
        clear.iter().any(|a| a.ip() == IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        "{clear:?}"
    );
    assert!(
        !clear.contains(&cjdns_sock),
        "fc00 must not dial without --cjdns-reachable: {clear:?}"
    );

    let mut only = book.clone();
    only.set_only_net(vec![OnlyNet::Onion]);
    assert_eq!(only.take_dial_candidates_net(8, &HashSet::new(), &[]), vec![onion]);
    assert!(only.take_dial_candidates(8, &HashSet::new(), &[]).is_empty());

    let mut only = book.clone();
    only.set_only_net(vec![OnlyNet::I2p]);
    let got = only.take_dial_candidates_net(8, &HashSet::new(), &[]);
    assert!(got.contains(&i2p), "{got:?}");
    assert!(
        got.iter().all(|a| matches!(a, crate::NetAddr::I2p { .. })),
        "{got:?}"
    );
    assert!(only.take_dial_candidates(8, &HashSet::new(), &[]).is_empty());

    let mut only = book.clone();
    only.set_cjdns_reachable(true);
    only.set_only_net(vec![OnlyNet::Cjdns]);
    assert_eq!(only.take_dial_candidates(8, &HashSet::new(), &[]), vec![cjdns_sock]);

    let dir = rbitcoin_query::testutil::TempDir::labeled("overlay-peers").unwrap();
    let path = dir.join("peers");
    book.save(&path).unwrap();
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(body.starts_with("rbitcoin-peers-v2"), "{body}");
    assert!(body.contains(".b32.i2p:8333") && body.contains("fc00:"), "{body}");
    let loaded = crate::seeds::AddrMan::load(&path).unwrap();
    for want in [onion, i2p, cjdns] {
        assert!(
            loaded.entries().iter().any(|e| e.addr == want),
            "{want} must persist, got {:?}",
            loaded.entries()
        );
    }
}

#[test]
fn overlay_config() {
    dial_targets_roundtrip();
    let hub = PeerHub::new(rbitcoin_consensus::NodeClock::new());
    let am = Arc::new(Mutex::new(crate::seeds::AddrMan::new()));
    hub.set_addrman(am.clone());
    let pk = [
        0x79, 0xbc, 0xc6, 0x25, 0x18, 0x4b, 0x05, 0x19, 0x49, 0x75, 0xc2, 0x8b, 0x66, 0xb6, 0x6b,
        0x04, 0x69, 0xf7, 0xf6, 0x55, 0x6f, 0xb1, 0xac, 0x31, 0x89, 0xa7, 0x9b, 0x40, 0xdd, 0xa3,
        0x2f, 0x1f,
    ];
    learn_overlay(&hub, AddrV2::TorV3(pk), 8333, 1);
    learn_overlay(
        &hub,
        AddrV2::Ipv4(Ipv4Addr::new(1, 2, 3, 4)),
        18444,
        1,
    );
    let onion = onion_addr();
    assert!(book_has(&am, onion));
    let i2p_early = crate::NetAddr::I2p {
        dest: [0x33u8; 32],
        port: 0,
    };
    learn_overlay(&hub, AddrV2::I2p([0x33u8; 32]), 0, 2);
    assert!(
        !book_has(&am, i2p_early),
        "unreachable I2P must not enter addrman"
    );
    hub.set_i2p_reachable(true);
    let i2p = crate::NetAddr::I2p {
        dest: [0x11u8; 32],
        port: 8333,
    };
    let i2p0 = crate::NetAddr::I2p {
        dest: [0x22u8; 32],
        port: 0,
    };
    learn_overlay(&hub, AddrV2::I2p([0x11u8; 32]), 8333, 3);
    learn_overlay(&hub, AddrV2::I2p([0x22u8; 32]), 0, 4);
    assert!(book_has(&am, i2p));
    assert!(book_has(&am, i2p0));
    let cjdns_ip = Ipv6Addr::new(0xfc00, 1, 2, 3, 4, 5, 6, 7);
    let cjdns = crate::NetAddr::Cjdns {
        ip: cjdns_ip,
        port: 8333,
    };
    learn_overlay(&hub, AddrV2::Cjdns(cjdns_ip), 8333, 5);
    assert!(book_has(&am, cjdns));
    only_net_dials_and_peers_file(&am, [onion, i2p, cjdns]);

    let bind = SocketAddr::from(([127, 0, 0, 1], 18444));
    let v1 = hub.addr_response_for_bind(bind);
    assert!(
        v1.iter().all(|(_, a)| a.socket_addr().is_ok()),
        "v1 ADDR omits overlay addresses: {v1:?}"
    );
    assert!(!v1.is_empty(), "v1 ADDR still serves the IPv4");
    let ip = crate::NetAddr::Ip(SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 18444)));
    for (i, addr) in [onion, i2p, i2p0, cjdns, ip].into_iter().enumerate() {
        let mut one = crate::seeds::AddrMan::new();
        one.add_addr(addr);
        hub.set_addrman(Arc::new(Mutex::new(one)));
        let bind = SocketAddr::from(([127, 0, 0, 1], 19000 + i as u16));
        let got: Vec<_> = hub
            .addr_response_net(bind, true)
            .into_iter()
            .map(|(_, a)| a)
            .collect();
        assert_eq!(got, vec![addr], "{addr}");
        let v1_len = hub.addr_response_for_bind(bind).len();
        if matches!(addr, crate::NetAddr::Ip(_)) {
            assert_eq!(v1_len, 1);
        } else {
            assert_eq!(v1_len, 0, "v1 ADDR omits overlay {addr}");
        }
    }

    inbound_fc00_is_cjdns(&hub);
    advertise_then_self_announce(&hub);
}
