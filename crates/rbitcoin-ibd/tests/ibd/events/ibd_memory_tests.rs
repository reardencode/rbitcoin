//! Header-path and body-intake bounds (findings C03, C05).
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rbitcoin_ibd::ibd::state::IbdWorkState;
use std::sync::atomic::AtomicU32;

use bitcoin::consensus::encode::serialize;
use rbitcoin_ibd::ibd::events::{
    accepted_prefix_after_failure, apply_block_framed, on_headers_batch,
};

use bitcoin::Block;

fn stored_batch(
    st: &mut IbdWorkState,
    hub: &rbitcoin_net::chain::ChainHub,
    peer: usize,
    headers: Vec<bitcoin::block::Header>,
) -> usize {
    let known: Vec<_> = headers
        .iter()
        .map_while(|h| st.header_fks.get(&h.block_hash()).copied())
        .collect();
    let (fks, work) = rbitcoin_ibd::ibd::events::fks_for_kept(&known, hub, &headers[known.len()..]);
    on_headers_batch(st, hub, peer, headers, &fks, work)
}

fn tmp_hub() -> (
    rbitcoin_query::testutil::TempDir,
    rbitcoin_net::chain::ChainHub,
) {
    rbitcoin_net::chain::tiny_regtest_hub_labeled("ibd-memory")
}

fn mine(prev: BlockHash, time: u32, height: u32) -> Block {
    rbitcoin_consensus::mine_empty_regtest(prev, time, height)
}

#[test]
fn rejected_header_batch_does_not_grow_path_or_explore() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    let path_before = st.hash_height.len();
    let mut bad = mine(gen, 1_500_010_000, 1);
    bad.header.time = 0;
    stored_batch(&mut st, &hub, 0, vec![bad.header]);
    assert_eq!(
        st.hash_height.len(),
        path_before,
        "invalid header must not enter the work path"
    );
    assert!(st.reorg.explore_need_hashes().is_empty());
    assert!(st.reorg.explore_tips().is_empty());

    let good = mine(gen, 1_500_010_000, 1);
    let (good_fks, _) = rbitcoin_ibd::ibd::events::prepare_header_store(&hub, &[good.header]);
    assert_eq!(
        good_fks.len(),
        1,
        "a full good batch is stored as that batch"
    );
    assert!(hub
        .query
        .get_header_by_hash(&good.block_hash().to_byte_array())
        .unwrap()
        .is_some());
    stored_batch(&mut st, &hub, 0, vec![good.header]);
    assert!(
        st.hash_height.contains_key(&good.block_hash()),
        "a valid header still records path state"
    );
    let tipped = hub
        .query
        .milestone_best_work_be()
        .expect("a header on the tip passes chain work into the milestone path");
    let expect = (hub.chain_work().unwrap() + good.header.work()).to_be_bytes();
    assert_eq!(tipped, expect);

    let mut child = mine(good.block_hash(), 1_500_010_600, 2);
    child.header.time = 0;
    let broken = child.header.block_hash();
    stored_batch(&mut st, &hub, 0, vec![good.header, child.header]);
    assert!(
        st.hash_height.contains_key(&good.block_hash()),
        "the valid prefix stays on the path"
    );
    assert!(
        !st.hash_height.contains_key(&broken),
        "header after a failed validation must not be noted"
    );

    // `good` was stored before this pair, so a search that returns nothing
    // still leaves it on the path. A fresh prefix has to be found by the
    // binary search or it never enters the work path.
    let fresh = mine(good.block_hash(), 1_500_011_200, 2);
    let mut bad_tail = mine(fresh.block_hash(), 1_500_011_800, 3);
    bad_tail.header.time = 0;
    let fresh_hash = fresh.block_hash();
    let tail_hash = bad_tail.header.block_hash();
    let (prefix_fks, _) =
        rbitcoin_ibd::ibd::events::prepare_header_store(&hub, &[fresh.header, bad_tail.header]);
    assert_eq!(
        prefix_fks.len(),
        1,
        "a rejected tail is absent from the stored prefix"
    );
    let stored_fresh = hub
        .query
        .get_header_by_hash(&fresh_hash.to_byte_array())
        .unwrap();
    assert_eq!(stored_fresh.map(|(fk, _)| fk), Some(prefix_fks[0]));
    assert!(hub
        .query
        .get_header_by_hash(&tail_hash.to_byte_array())
        .unwrap()
        .is_none());
    let added = stored_batch(&mut st, &hub, 0, vec![fresh.header, bad_tail.header]);
    assert!(
        st.hash_height.contains_key(&fresh_hash),
        "binary search must keep the valid prefix of a rejected tail"
    );
    assert!(added >= 1, "the valid prefix is enqueued");
    assert!(
        !st.hash_height.contains_key(&tail_hash),
        "rejected tail must not be noted"
    );

    let second = mine(fresh.block_hash(), 1_500_012_200, 3);
    let mut bad_third = mine(second.block_hash(), 1_500_012_800, 4);
    bad_third.header.time = 0;
    let second_hash = second.block_hash();
    stored_batch(
        &mut st,
        &hub,
        0,
        vec![fresh.header, second.header, bad_third.header],
    );
    assert!(
        st.hash_height.contains_key(&second_hash),
        "both headers before a rejected tail stay on the path"
    );
    assert!(!st.hash_height.contains_key(&bad_third.header.block_hash()));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn unsolicited_body_is_not_copied_into_the_queue() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let block = mine(gen, 1_500_020_000, 1);
    let hash = block.block_hash();
    let payload = serialize(&block);
    let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    st.record_height(hash, 1);
    st.header_fks.insert(hash, rbitcoin_primitives::Fk(1));
    let before = hub.query.block_queue_stats().0;
    let write_next = AtomicU32::new(0);
    apply_block_framed(
        &mut st,
        &hub,
        &write_next,
        None,
        rbitcoin_ibd::ibd::events::FramedBody {
            peer: 0,
            hash,
            payload: payload.clone(),
            header_fk: None,
        },
    );
    assert_eq!(
        hub.query.block_queue_stats().0,
        before,
        "unsolicited body must not be copied into the queue"
    );

    st.inflight
        .insert(hash, rbitcoin_ibd::ibd::state::InflightReq::new(0));
    apply_block_framed(
        &mut st,
        &hub,
        &write_next,
        None,
        rbitcoin_ibd::ibd::events::FramedBody {
            peer: 0,
            hash,
            payload,
            header_fk: None,
        },
    );
    assert!(
        hub.query.block_queue_stats().0 > before,
        "a requested body is still queued"
    );
    let queued = hub.query.block_queue_stats().0;
    st.inflight
        .insert(hash, rbitcoin_ibd::ibd::state::InflightReq::new(0));
    apply_block_framed(
        &mut st,
        &hub,
        &write_next,
        None,
        rbitcoin_ibd::ibd::events::FramedBody {
            peer: 0,
            hash,
            payload: serialize(&block),
            header_fk: None,
        },
    );
    assert_eq!(
        hub.query.block_queue_stats().0,
        queued,
        "a second copy of a queued hash is dropped"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A second hash at a height that already has a body is not a bad peer.
/// The queued body stays, and the new hash is pending rather than missing.
#[test]
fn undecodable_body_at_occupied_height_keeps_the_peer() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let block = mine(gen, 1_500_020_000, 1);
    let hash = block.block_hash();
    let mut st = IbdWorkState::new(
        vec![super::super::assign::dummy_slot(0)],
        hub.tip_hash(),
        hub.tip_height(),
    );
    st.record_height(hash, 1);
    st.header_fks.insert(hash, rbitcoin_primitives::Fk(1));
    st.inflight
        .insert(hash, rbitcoin_ibd::ibd::state::InflightReq::new(0));
    let write_next = AtomicU32::new(0);
    apply_block_framed(
        &mut st,
        &hub,
        &write_next,
        None,
        rbitcoin_ibd::ibd::events::FramedBody {
            peer: 0,
            hash,
            payload: serialize(&block),
            header_fk: None,
        },
    );
    let queued = hub.query.block_queue_stats().0;
    assert!(queued > 0, "the first body is queued");
    assert_eq!(
        hub.query.block_queue_hash_at_height(1),
        Some(hash.to_byte_array())
    );

    let mut raw = [0u8; 32];
    raw[0] = 0xab;
    let other = BlockHash::from_byte_array(raw);
    st.record_height(other, 1);
    st.header_fks.insert(other, rbitcoin_primitives::Fk(1));
    st.inflight
        .insert(other, rbitcoin_ibd::ibd::state::InflightReq::new(0));
    apply_block_framed(
        &mut st,
        &hub,
        &write_next,
        None,
        rbitcoin_ibd::ibd::events::FramedBody {
            peer: 0,
            hash: other,
            payload: b"not a block".to_vec(),
            header_fk: None,
        },
    );
    assert!(
        st.slots[0].alive,
        "an occupied height is not a reason to drop the peer"
    );
    assert!(st.body.is_pending(&other));
    assert!(!st.body.is_missing(&other));
    assert_eq!(hub.query.block_queue_stats().0, queued);
    assert_eq!(
        hub.query.block_queue_hash_at_height(1),
        Some(hash.to_byte_array())
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// One genesis chain. A re-sent stored run does not walk, an unmapped run
/// walks once, an unknown parent is not retried, and a time-0 header is
/// not stored.
#[test]
fn stored_header_resends_walk_once() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let mut chain = Vec::new();
    let mut prev = gen;
    for height in 1..=240u32 {
        let header = mine(prev, 1_500_030_000 + height * 600, height).header;
        prev = header.block_hash();
        chain.push(header);
    }
    let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    stored_batch(&mut st, &hub, 0, chain[..200].to_vec());
    let _ = hub.take_stored_height_walk_steps();
    stored_batch(&mut st, &hub, 0, chain[100..200].to_vec());
    assert_eq!(
        hub.take_stored_height_walk_steps(),
        0,
        "a re-sent run of stored headers walks no ancestors"
    );
    stored_batch(&mut st, &hub, 0, chain.clone());
    assert_eq!(
        hub.take_stored_height_walk_steps(),
        0,
        "a stored prefix before new headers walks no ancestors"
    );
    for (height, header) in (1u32..).zip(&chain) {
        assert_eq!(
            st.hash_height.get(&header.block_hash()),
            Some(&height),
            "every header, stored or new, stays on the path at its height"
        );
    }

    let mut fresh = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    let _ = hub.take_stored_height_walk_steps();
    stored_batch(&mut fresh, &hub, 0, chain[..200].to_vec());
    assert_eq!(
        hub.take_stored_height_walk_steps(),
        1,
        "a stored run outside header_fks walks only its first header"
    );
    for (height, header) in (1u32..).zip(&chain[..200]) {
        assert_eq!(
            fresh.hash_height.get(&header.block_hash()),
            Some(&height),
            "every stored header is on the path at its height"
        );
    }

    let unknown = BlockHash::from_byte_array([0x7d; 32]);
    let mut side = Vec::new();
    let mut prev = unknown;
    for height in 1..=20u32 {
        let header = mine(prev, 1_500_050_000 + height * 600, height).header;
        prev = header.block_hash();
        side.push(header);
    }
    let mut side_st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    stored_batch(&mut side_st, &hub, 0, side.clone());
    assert!(side_st.header_fks.is_empty());
    for header in &side {
        assert!(!side_st.hash_height.contains_key(&header.block_hash()));
    }

    let parent = chain[11].block_hash();
    let mut rejected = mine(parent, 1_500_030_000 + 13 * 600, 13).header;
    rejected.time = 0;
    let mut batch = chain[4..12].to_vec();
    batch.push(rejected);
    let mut tail = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    stored_batch(&mut tail, &hub, 0, batch);
    for header in &chain[4..12] {
        assert!(tail.header_fks.contains_key(&header.block_hash()));
    }
    assert!(
        !tail.header_fks.contains_key(&rejected.block_hash()),
        "a time-0 header is not stored"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn failed_first_prefix_stops_search() {
    let mut probes = Vec::new();
    let (lo, values): (usize, Vec<u32>) = accepted_prefix_after_failure(2000, |mid| {
        probes.push(mid);
        Err(rbitcoin_net::error::NetError::Protocol(
            "first header rejected",
        ))
    });
    assert_eq!(lo, 0);
    assert!(values.is_empty());
    assert_eq!(
        probes,
        vec![1],
        "do not retry longer prefixes after first header fails"
    );

    let mut probes = Vec::new();
    let (lo, values) = accepted_prefix_after_failure(2000, |mid| {
        probes.push(mid);
        if mid <= 731 {
            Ok((1..=mid).collect::<Vec<_>>())
        } else {
            Err(rbitcoin_net::error::NetError::Protocol("rejected tail"))
        }
    });
    assert_eq!(lo, 731);
    assert_eq!(values.len(), lo);
    assert_eq!(values[0], 1);
    assert_eq!(values[lo - 1], 731);
    assert_eq!(probes[0], 1);
}
