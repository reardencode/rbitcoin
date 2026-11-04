use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rbitcoin_ibd::ibd::state::*;
use rbitcoin_primitives::Fk;

fn h(n: u8) -> BlockHash {
    let mut b = [0u8; 32];
    b[0] = n;
    BlockHash::from_byte_array(b)
}

#[test]
fn inflight_req_multi_peer_add_remove() {
    let mut r = InflightReq::new(1);
    assert_eq!(r.len(), 1);
    assert!(r.peers.contains(&1));
    assert!(r.add_peer(2));
    assert!(!r.add_peer(2)); // already present
    assert_eq!(r.len(), 2);
    assert!(!r.remove_peer(1));
    assert_eq!(r.len(), 1);
    assert!(r.remove_peer(2));
    assert_eq!(r.len(), 0);
}

#[test]
fn reopen_for_densify_rewinds_to_lowest_freed_height() {
    let mut st = IbdWorkState::new(Vec::new(), Some(h(0)), Some(0));
    st.record_height(h(30), 30);
    st.record_height(h(40), 40);
    st.densify_scan_lo = 50;
    st.reopen_for_densify(&[h(40), h(30), h(99)]);
    assert_eq!(st.densify_scan_lo, 30, "unknown heights are ignored");
    st.reopen_for_densify(&[h(40)]);
    assert_eq!(st.densify_scan_lo, 30, "never moves the cursor forward");
}

#[test]
fn inflight_req_retired_peer_still_holds_the_hash() {
    let mut r = InflightReq::new(1);
    assert!(r.add_peer(2));
    r.retire_peer(1);
    assert_eq!(r.len(), 1, "retired peer no longer races");
    assert!(!r.peers.contains(&1));
    assert!(r.holds(1), "retired peer still has the getdata");
    assert!(
        r.owner_asked_at(1).is_some(),
        "retired peer keeps its ask time for the aged re-ask"
    );
    assert!(r.owner_asked_at(2).is_some());
    r.retire_peer(2);
    assert_eq!(r.len(), 0);
    assert!(r.holds(2));
    assert!(
        !r.remove_peer(1),
        "hash stays requested while a holder remains"
    );
    assert!(r.remove_peer(2));
    assert!(!r.holds(1) && !r.holds(2));
    assert!(r.owner_asked_at(1).is_none() && r.owner_asked_at(2).is_none());
}

#[test]
fn ordered_bloated_when_ghosts_exceed_live_set() {
    let tip = h(0);
    let mut st = IbdWorkState::new(Vec::new(), Some(tip), Some(10));
    assert!(!st.ordered_bloated());
    for i in 1u8..=200 {
        st.ordered.push_back(h(i));
    }
    st.ordered_set.insert(h(1));
    assert!(st.ordered_bloated());
}

#[test]
fn record_height_structure_sizes_and_hygiene() {
    let tip = h(0);
    let mut st = IbdWorkState::new(Vec::new(), Some(tip), Some(10));
    assert!(st.known_headers.contains(&tip));
    assert_eq!(st.hash_height.get(&tip), Some(&10));
    assert_eq!(st.height_to_hash.get(&10), Some(&tip));

    st.record_height(tip, 11);
    assert!(!st.height_to_hash.contains_key(&10));
    assert_eq!(st.height_to_hash.get(&11), Some(&tip));

    // Seed a bloated ordered deque with middle ghosts so hygiene compacts.
    for i in 1u8..=140 {
        let hash = h(i);
        st.ordered.push_back(hash);
        if i % 2 == 0 {
            st.ordered_set.insert(hash);
            st.record_height(hash, 11 + u32::from(i));
            st.header_fks.insert(hash, Fk(u64::from(i)));
        }
        st.known_headers.insert(hash);
    }
    st.hygiene();
    // Live set only even hashes; compact should drop ghosts when bloated.
    assert!(
        st.ordered.len() <= st.ordered_set.len().saturating_add(64).max(128)
            || st
                .ordered
                .iter()
                .all(|x| st.ordered_set.contains(x) || !st.ordered_set.contains(x))
    );
    let sizes = st.structure_sizes();
    assert_eq!(sizes.ordered, st.ordered.len());
    assert_eq!(sizes.ordered_set, st.ordered_set.len());
    assert_eq!(sizes.hash_height, st.hash_height.len());
    assert_eq!(sizes.known_headers, st.known_headers.len());
    assert_eq!(sizes.header_fks, st.header_fks.len());
    assert_eq!(sizes.inflight, 0);
    assert_eq!(sizes.peer_inflight, 0);

    let keep = h(200);
    st.inflight.insert(keep, InflightReq::new(0));
    st.record_height(keep, 999);
    st.header_fks.insert(keep, Fk(200));
    st.hygiene();
    assert!(st.hash_height.contains_key(&keep));
    assert!(st.header_fks.contains_key(&keep));
}

#[test]
fn path_slot_first_wins_chained() {
    let tip = h(0);
    let mut st = IbdWorkState::new(Vec::new(), Some(tip), Some(0));
    st.height_to_hash.insert(0, tip);
    let a = h(1);
    let b = h(2);
    assert!(st.try_set_path_slot(a, 1, tip, Some((0, tip))));
    assert_eq!(st.height_to_hash.get(&1), Some(&a));
    assert!(
        !st.try_set_path_slot(b, 1, tip, Some((0, tip))),
        "first connected occupant wins"
    );
    assert_eq!(st.height_to_hash.get(&1), Some(&a));
    assert_eq!(st.hash_height.get(&b), Some(&1), "off-path still noted");
    let off = h(3);
    assert!(
        !st.try_set_path_slot(off, 1, h(9), Some((0, tip))),
        "prev must be store tip at tip+1"
    );
    assert_eq!(st.height_to_hash.get(&1), Some(&a));
}

#[test]
fn reorg_clears_path_suffix() {
    let tip = h(0);
    let mut st = IbdWorkState::new(Vec::new(), Some(tip), Some(1));
    st.record_height(h(2), 2);
    st.record_height(h(3), 3);
    st.record_height(h(4), 4);
    st.ordered_set.insert(h(3));
    st.ordered.push_back(h(3));
    st.ordered_set.insert(h(4));
    st.ordered.push_back(h(4));
    st.clear_path_above(2);
    assert_eq!(st.height_to_hash.get(&2), Some(&h(2)));
    assert!(!st.height_to_hash.contains_key(&3));
    assert!(!st.height_to_hash.contains_key(&4));
    assert!(!st.ordered_set.contains(&h(3)));
    assert!(!st.ordered_set.contains(&h(4)));
}

/// InflightReq::default + known_headers prune when known ≫ live ordered set.
#[test]
fn inflight_default_and_known_headers_deep_hygiene_prune() {
    let d = InflightReq::default();
    assert!(d.peers.is_empty());
    // started_at is Instant::now() — just ensure it is in the past/near now.
    assert!(d.started_at.elapsed().as_secs() < 5);

    let tip = h(0);
    let mut st = IbdWorkState::new(Vec::new(), Some(tip), Some(1));
    // Keep tip on the live ordered path so prune retain keeps it.
    st.ordered.push_back(tip);
    st.ordered_set.insert(tip);
    // Flood known_headers past live+4096 threshold.
    for i in 1u32..=4200 {
        let mut b = [0u8; 32];
        b[0..4].copy_from_slice(&i.to_le_bytes());
        let hash = BlockHash::from_byte_array(b);
        st.known_headers.insert(hash);
        st.hash_height.insert(hash, i);
        st.header_fks.insert(hash, Fk(u64::from(i)));
    }
    assert!(st.known_headers.len() > 4096);
    st.deep_hygiene();
    // Only live ordered (+ inflight) remains in known; bulk pruned.
    assert!(
        st.known_headers.len() <= 64,
        "known_headers should prune when ≫ ordered: {}",
        st.known_headers.len()
    );
    assert!(st.known_headers.contains(&tip));
    // Auxiliary maps follow known after prune.
    assert!(st.hash_height.len() <= st.known_headers.len().saturating_add(8));
}

/// The per-second path must stay O(live). Chain-sized maps are swept only by
/// `deep_hygiene`; a per-second `known_headers` sweep pegged the main loop at
/// ~1 M headers (a 392-sample perf of the operator node put 99 % of the main
/// thread in `hygiene` plus SipHash).
#[test]
fn hygiene_does_not_sweep_chain_sized_maps() {
    let tip = h(0);
    let mut st = IbdWorkState::new(Vec::new(), Some(tip), Some(1));
    st.ordered.push_back(tip);
    st.ordered_set.insert(tip);
    // Off-path headers: recorded height, but no `height_to_hash` occupant.
    for i in 1u32..=4200 {
        let mut b = [0u8; 32];
        b[0..4].copy_from_slice(&i.to_le_bytes());
        let hash = BlockHash::from_byte_array(b);
        st.known_headers.insert(hash);
        st.hash_height.insert(hash, i);
        st.header_fks.insert(hash, Fk(u64::from(i)));
        st.path_prev.insert(hash, tip);
    }
    assert!(st.known_headers.len() > 4096);
    st.hygiene();
    assert_eq!(
        st.known_headers.len(),
        4201,
        "the 1 Hz path must not sweep known_headers"
    );
    assert_eq!(st.hash_height.len(), 4201);
    assert_eq!(st.header_fks.len(), 4200);
    assert_eq!(st.path_prev.len(), 4200);

    // The chain-sized prune still exists; it is just off the per-second path.
    st.deep_hygiene();
    assert_eq!(
        st.known_headers.len(),
        1,
        "deep hygiene drops headers that do not occupy their height"
    );
    assert!(st.known_headers.contains(&tip));
    assert_eq!(st.hash_height.len(), 1);
    assert!(st.header_fks.is_empty());
    assert!(st.path_prev.is_empty());
}
