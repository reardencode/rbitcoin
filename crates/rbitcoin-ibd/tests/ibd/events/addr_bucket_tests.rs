use super::super::assign::dummy_slot;
use rbitcoin_ibd::ibd::peer_io::ibd_mono_ms;
use rbitcoin_ibd::ibd::state::IbdWorkState;
use rbitcoin_net::seeds::AddrMan;

use rbitcoin_ibd::ibd::events::{apply_peer_dead, take_addr_tokens};

/// IBD peers spend the same addr token bucket as tip-follow sessions: one
/// token at connect, so a 1000-address flood teaches the book one address.
#[test]
fn ibd_peer_addr_flood_takes_one_token() {
    let mut slot = dummy_slot(1);
    slot.connected_ms = ibd_mono_ms();
    let mut st = IbdWorkState::new(vec![slot], None, Some(0));
    assert_eq!(take_addr_tokens(&mut st, 1, 1_000), 1);
    assert_eq!(
        take_addr_tokens(&mut st, 1, 1_000),
        0,
        "the bucket is spent"
    );
    let mut book = AddrMan::new();
    apply_peer_dead(&mut st, &mut book, 1, "bye".to_string());
    assert!(
        st.addr_buckets.is_empty(),
        "a dead peer's bucket is dropped"
    );
}

/// An outbound `addr` whitelist exempts an IBD peer as it does a
/// tip-follow session.
#[test]
fn ibd_addr_permission_peer_is_not_rate_limited() {
    let mut slot = dummy_slot(1);
    slot.connected_ms = ibd_mono_ms();
    let ip = slot.addr.ip();
    let mut st = IbdWorkState::new(vec![slot], None, Some(0));
    let peers = rbitcoin_net::peers::PeerHub::new(rbitcoin_consensus::NodeClock::new());
    let mut table = rbitcoin_net::net_permissions::NetPermTable::default();
    table
        .whitelist
        .push(rbitcoin_net::net_permissions::parse_whitelist(&format!("addr,out@{ip}")).unwrap());
    peers.set_net_perms(table);
    st.perms = Some(peers);
    assert_eq!(take_addr_tokens(&mut st, 1, 1_000), 1_000);
    assert_eq!(
        take_addr_tokens(&mut st, 1, 1_000),
        1_000,
        "an addr-permission peer is never limited"
    );
}
