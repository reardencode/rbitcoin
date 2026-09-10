//! Ordered work-path seeding and header locator tips.

use super::state::IbdWorkState;
use super::MAX_ORDERED_HEADERS;
use crate::chain::ChainHub;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rbitcoin_log::{info, warn};
use std::time::Instant;

pub(crate) fn seed_work_path_from_store(st: &mut IbdWorkState, hub: &ChainHub) {
    let Some(tip_hash) = hub.tip_hash() else {
        return;
    };
    let tip_h = hub.tip_height().unwrap_or(0);
    let t0 = Instant::now();
    // Operator breadcrumb: crash between "peers ready" and this line is in
    // resume_work_path (header graph walk), not getdata assign.
    info!("ibd: resume seed walk start tip={tip_h} max_ordered={MAX_ORDERED_HEADERS}");
    let exclude: Vec<[u8; 32]> = st.reorg.invalid.iter().collect();
    let path = match hub.query.resume_work_path_after_tip_excluding(
        tip_hash.to_byte_array(),
        tip_h,
        MAX_ORDERED_HEADERS,
        &exclude,
    ) {
        Ok(p) => p,
        Err(e) => {
            warn!("ibd: resume seed from store failed: {e}");
            return;
        }
    };
    if path.is_empty() {
        return;
    }
    let mut explore_is_sibling_fork = false;
    let mut explore_need = Vec::new();
    for e in &path {
        let hash = BlockHash::from_byte_array(e.hash);
        if st.reorg.invalid.contains(e.hash) {
            break;
        }
        st.known_headers.insert(hash);
        st.hash_height.insert(hash, e.height);
        st.header_fks.insert(hash, e.header_fk);
        if e.height <= tip_h && hash != tip_hash {
            explore_is_sibling_fork = true;
            if !e.has_body {
                explore_need.push(hash);
            }
        } else if explore_is_sibling_fork && !e.has_body && explore_need.len() < 4 {
            explore_need.push(hash);
        }
    }
    if explore_is_sibling_fork {
        let explore_tip = path
            .iter()
            .rev()
            .find(|e| !st.reorg.invalid.contains(e.hash))
            .map(|e| BlockHash::from_byte_array(e.hash));
        st.reorg.register_explore(explore_need, explore_tip);
        match super::reorg::maybe_rewind_to_best_work(st, hub) {
            Ok(true) => {
                info!(
                    "ibd: resume seed rewound to most-work header path (store walk {:?})",
                    t0.elapsed()
                );
                return;
            }
            Ok(false) => {
                info!(
                    "ibd: resume seed greater-work sibling fork explore_need={} explore_tip={:?}",
                    st.reorg.need_getdata().len(),
                    explore_tip
                );
            }
            Err(e) => {
                warn!("ibd: resume seed most-work rewind failed: {e}");
            }
        }
    }
    let mut with_body = 0u32;
    let mut ready_prefix_to = tip_h;
    let mut ready_prefix = true;
    let tip = hub.tip_height().zip(hub.tip_hash());
    for e in &path {
        if st.reorg.invalid.contains(e.hash) {
            break;
        }
        let hash = BlockHash::from_byte_array(e.hash);
        let prev = if e.height == 0 {
            BlockHash::from_byte_array([0u8; 32])
        } else {
            st.height_to_hash
                .get(&e.height.saturating_sub(1))
                .copied()
                .or_else(|| {
                    tip.filter(|(th, _)| e.height == th.saturating_add(1))
                        .map(|(_, h)| h)
                })
                .unwrap_or(BlockHash::from_byte_array([0u8; 32]))
        };
        let on_path = st.try_set_path_slot(hash, e.height, prev, tip);
        st.max_ordered_height = st.max_ordered_height.max(e.height);
        if on_path && st.ordered_set.insert(hash) {
            st.ordered.push_back(hash);
        }
        if e.has_body {
            st.body.mark_archived(hash);
            with_body = with_body.saturating_add(1);
            if ready_prefix {
                ready_prefix_to = e.height;
            }
        } else {
            ready_prefix = false;
        }
    }
    st.max_ready_height = st.max_ready_height.max(ready_prefix_to);
    st.headers_done = false;
    info!(
        "ibd: resume seed ordered={} class_a_bodies={} ready_to={} (store walk {:?})",
        st.ordered.len(),
        with_body,
        ready_prefix_to,
        t0.elapsed()
    );
    plant_valid_tip_child(st, hub);
}

/// If tip+1 is missing or invalid, plant a known valid sibling/child of tip.
pub(crate) fn plant_valid_tip_child(st: &mut IbdWorkState, hub: &ChainHub) {
    let Some(tip_hash) = hub.tip_hash() else {
        return;
    };
    let tip_h = hub.tip_height().unwrap_or(0);
    let expect = if hub.tip_height().is_none() {
        0u32
    } else {
        tip_h.saturating_add(1)
    };
    if let Some(&cur) = st.height_to_hash.get(&expect) {
        if !st.reorg.invalid.contains(cur.to_byte_array()) && !st.body.is_rejected(&cur) {
            return;
        }
    }
    let mut child: Option<BlockHash> = None;
    for (&h, &ht) in &st.hash_height {
        if ht != expect {
            continue;
        }
        if st.reorg.invalid.contains(h.to_byte_array()) || st.body.is_rejected(&h) {
            continue;
        }
        let Ok(Some(prev)) = super::reorg::parent_hash_of(hub, h) else {
            continue;
        };
        if prev != tip_hash {
            continue;
        }
        child = Some(h);
        break;
    }
    let Some(child) = child else {
        return;
    };
    let tip = hub.tip_height().zip(hub.tip_hash());
    let mut prev = tip_hash;
    let mut cur = child;
    let mut ht = expect;
    for _ in 0..MAX_ORDERED_HEADERS {
        if st.reorg.invalid.contains(cur.to_byte_array()) || st.body.is_rejected(&cur) {
            break;
        }
        let on_path = st.try_set_path_slot(cur, ht, prev, tip);
        st.max_ordered_height = st.max_ordered_height.max(ht);
        if on_path && st.ordered_set.insert(cur) {
            st.ordered.push_back(cur);
        }
        st.known_headers.insert(cur);
        prev = cur;
        ht = ht.saturating_add(1);
        let next = st.height_to_hash.get(&ht).copied().or_else(|| {
            st.hash_height
                .iter()
                .find(|(_, &hht)| hht == ht)
                .map(|(h, _)| *h)
        });
        let Some(n) = next else {
            break;
        };
        let Ok(Some(p)) = super::reorg::parent_hash_of(hub, n) else {
            break;
        };
        if p != cur {
            break;
        }
        cur = n;
    }
}

/// Highest hashes on the download path (newest first) for getheaders locators.
///
/// Includes proactive exploration tips (greater-work sibling path) so empty
/// getheaders lag can re-root onto the heavier store chain.
pub(crate) fn work_path_tips(st: &IbdWorkState) -> Vec<BlockHash> {
    let mut tips = Vec::with_capacity(8);
    // ordered is tip→far; the back is the highest known header on the path.
    let live =
        |h: &BlockHash| !st.reorg.invalid.contains(h.to_byte_array()) && !st.body.is_rejected(h);
    for h in st.ordered.iter().rev().take(4) {
        if st.ordered_set.contains(h) && live(h) {
            tips.push(*h);
        }
    }
    for h in st.reorg.explore_tips() {
        if !live(h) {
            continue;
        }
        if !tips.contains(h) {
            tips.push(*h);
        }
        if tips.len() >= 8 {
            break;
        }
    }
    if tips.is_empty() {
        if let Some((&h, _)) = st
            .hash_height
            .iter()
            .filter(|(h, _)| live(h))
            .max_by_key(|(_, &ht)| ht)
        {
            tips.push(h);
        }
    }
    tips
}

/// Connected work-path hashes strictly above `tip_h` (`height_to_hash` occupants).
///
/// Competing `hash_height` entries are not path work — hard reset must not
/// promote them onto `ordered`.
pub(crate) fn path_hashes_above_tip(st: &IbdWorkState, tip_h: u32) -> Vec<(u32, BlockHash)> {
    let mut above: Vec<(u32, BlockHash)> = st
        .height_to_hash
        .iter()
        .filter(|(&ht, _)| ht > tip_h)
        .map(|(&ht, &h)| (ht, h))
        .collect();
    above.sort_by_key(|(ht, _)| *ht);
    above
}

#[cfg(test)]
mod tests {
    use super::super::state::IbdWorkState;
    use super::path_hashes_above_tip;
    use super::work_path_tips;
    use bitcoin::hashes::Hash;
    use bitcoin::BlockHash;

    fn h(n: u8) -> BlockHash {
        let mut b = [0u8; 32];
        b[0] = n;
        BlockHash::from_byte_array(b)
    }

    #[test]
    fn work_path_tips_from_ordered_newest_first() {
        let mut st = IbdWorkState::new(Vec::new(), None, Some(10));
        // ordered is tip→far (front near tip); tips take from the back (highest).
        for n in 1u8..=6 {
            let hash = h(n);
            st.ordered.push_back(hash);
            st.ordered_set.insert(hash);
            st.record_height(hash, 10 + u32::from(n));
        }
        let tips = work_path_tips(&st);
        assert_eq!(tips.len(), 4);
        assert_eq!(tips[0], h(6));
        assert_eq!(tips[1], h(5));
        assert_eq!(tips[2], h(4));
        assert_eq!(tips[3], h(3));
    }

    #[test]
    fn work_path_tips_skips_ghosts_and_falls_back_to_hash_height() {
        let mut st = IbdWorkState::new(Vec::new(), None, Some(0));
        // Ghost: in deque but not ordered_set.
        st.ordered.push_back(h(1));
        st.ordered.push_back(h(2));
        // No live ordered members → fall back to max height in hash_height.
        st.record_height(h(9), 99);
        st.record_height(h(8), 50);
        let tips = work_path_tips(&st);
        assert_eq!(tips, vec![h(9)]);

        // Empty everything → empty tips.
        let empty = IbdWorkState::new(Vec::new(), None, None);
        assert!(work_path_tips(&empty).is_empty());
    }

    #[test]
    fn work_path_tips_respects_live_set_only() {
        let mut st = IbdWorkState::new(Vec::new(), None, Some(1));
        st.ordered.push_back(h(1));
        st.ordered.push_back(h(2));
        st.ordered.push_back(h(3));
        st.ordered_set.insert(h(1));
        st.ordered_set.insert(h(3)); // h(2) is a middle ghost
        let tips = work_path_tips(&st);
        // rev walk: 3 (live), 2 (ghost skip), 1 (live) — only set members.
        assert_eq!(tips, vec![h(3), h(1)]);
    }

    #[test]
    fn path_hashes_above_tip_skips_competing_hash_height() {
        let mut st = IbdWorkState::new(Vec::new(), None, Some(10));
        let occupant = h(1);
        st.record_height(occupant, 11);
        st.hash_height.insert(h(9), 12);
        assert_eq!(path_hashes_above_tip(&st, 10), vec![(11, occupant)]);
        assert!(path_hashes_above_tip(&st, 11).is_empty());
    }

    #[test]
    fn work_path_tips_skips_invalid_and_rejected() {
        let mut st = IbdWorkState::new(Vec::new(), None, Some(10));
        for n in 1u8..=4 {
            let hash = h(n);
            st.ordered.push_back(hash);
            st.ordered_set.insert(hash);
            st.record_height(hash, 10 + u32::from(n));
        }
        st.reorg.invalid.mark(h(4).to_byte_array());
        st.body.mark_rejected(h(3));
        let tips = work_path_tips(&st);
        assert!(!tips.contains(&h(4)), "invalid tip must not be a locator");
        assert!(!tips.contains(&h(3)), "rejected tip must not be a locator");
        assert!(tips.contains(&h(2)));
    }

    /// Exploration tips merge into locator tips (cap 8, dedupe ordered members).
    #[test]
    fn work_path_tips_includes_explore_tips_capped() {
        let mut st = IbdWorkState::new(Vec::new(), None, Some(10));
        for n in 1u8..=3 {
            let hash = h(n);
            st.ordered.push_back(hash);
            st.ordered_set.insert(hash);
        }
        // Explore tips: one already on ordered (dedupe), plus many unique.
        let mut need = Vec::new();
        for n in 10u8..=20 {
            need.push(h(n));
        }
        st.reorg.register_explore(need, Some(h(20)));
        let tips = work_path_tips(&st);
        assert!(tips.contains(&h(3))); // ordered newest
        assert!(tips.contains(&h(20))); // explore tip
        assert!(tips.len() <= 8);
        // h(1) is on ordered (taken in first 4) so not re-added as explore.
        assert_eq!(tips.iter().filter(|x| **x == h(1)).count(), 1);
    }

    #[test]
    fn seed_work_path_from_empty_and_genesis_store() {
        use super::seed_work_path_from_store;

        let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("path-seed");
        // Empty store: tip_hash is None → seed returns immediately.
        let mut st = IbdWorkState::new(Vec::new(), None, None);
        seed_work_path_from_store(&mut st, &hub);
        assert!(st.ordered.is_empty());

        hub.ensure_genesis().unwrap();
        let mut st2 = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
        seed_work_path_from_store(&mut st2, &hub);
        // Resume path after tip may be empty (no headers beyond tip).
        assert!(!st2.headers_done); // always left open for peer tip
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Archive headers ahead of tip so resume seed walks a non-empty path
    /// (bodies + a body gap for the contiguous-prefix break).
    #[test]
    fn seed_work_path_archives_ahead_of_tip() {
        use super::seed_work_path_from_store;
        use bitcoin::absolute::LockTime;
        use bitcoin::block::{Header, Version};
        use bitcoin::script::ScriptBuf;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{
            Amount, Block, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxOut,
            Witness,
        };
        use rbitcoin_consensus::prepare_block_for_archive;

        let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("path-seed-arch");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();

        fn coinbase(height: u32) -> Transaction {
            let mut ss = if height == 0 {
                vec![0x00]
            } else {
                rbitcoin_consensus::bip34_height_script(height)
            };
            while ss.len() < 2 {
                ss.push(0x00);
            }
            Transaction {
                version: TxVersion::ONE,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::from_bytes(ss),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(50_0000_0000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            }
        }
        fn mine(prev: BlockHash, time: u32, height: u32) -> Block {
            let bits = CompactTarget::from_consensus(0x207f_ffff);
            let header = Header {
                version: Version::from_consensus(4),
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                time,
                bits,
                nonce: 0,
            };
            let mut block = Block {
                header,
                txdata: vec![coinbase(height)],
            };
            block.header.merkle_root = block.compute_merkle_root().unwrap();
            let target = Target::from_compact(bits);
            for nonce in 0..u32::MAX {
                block.header.nonce = nonce;
                if block.header.validate_pow(target).is_ok() {
                    break;
                }
            }
            block
        }

        // Tip stays at genesis; Class A at 1..=2 via the crash helper (not public
        // archive_block). Header-only height 3 breaks the contiguous-prefix.
        let mut tip = gen;
        let time = 1_300_000_000u32;
        for h in 1u32..=2 {
            let b = mine(tip, time + h * 600, h);
            hub.ensure_header(&b.header).unwrap();
            let (rec, txs) = prepare_block_for_archive(&hub.query, &hub.params, &b).unwrap();
            hub.query.commit_class_a_only(&rec, &txs).unwrap();
            tip = b.block_hash();
        }
        let b3 = mine(tip, time + 3 * 600, 3);
        hub.ensure_header(&b3.header).unwrap();
        // no Class A body for h=3 → ready_prefix breaks

        let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
        seed_work_path_from_store(&mut st, &hub);
        assert!(
            st.ordered.len() >= 2,
            "resume should seed work path after tip, got {}",
            st.ordered.len()
        );
        assert!(st.max_ordered_height >= 2);
        assert!(st.max_ready_height >= 2); // contiguous claim-ready prefix
        assert!(!st.headers_done);
        // Duplicates on re-seed only insert once into ordered_set.
        let n = st.ordered.len();
        seed_work_path_from_store(&mut st, &hub);
        assert_eq!(st.ordered.len(), n);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Tip on a short loser; heavier sibling headers in the store → rewind
    /// confirmed tip to the LCA and plant the winner as the linear work path.
    #[test]
    fn seed_rewinds_tip_to_lca_on_heavier_sibling() {
        use super::seed_work_path_from_store;
        use bitcoin::absolute::LockTime;
        use bitcoin::block::{Header, Version};
        use bitcoin::script::ScriptBuf;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{
            Amount, Block, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxOut,
            Witness,
        };

        let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("path-seed-sib");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();

        fn mine(prev: BlockHash, time: u32, height: u32) -> Block {
            let bits = CompactTarget::from_consensus(0x207f_ffff);
            let mut ss = if height == 0 {
                vec![0x00]
            } else {
                rbitcoin_consensus::bip34_height_script(height)
            };
            while ss.len() < 2 {
                ss.push(0x00);
            }
            let coinbase = Transaction {
                version: TxVersion::ONE,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::from_bytes(ss),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(50_0000_0000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            };
            let header = Header {
                version: Version::from_consensus(4),
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                time,
                bits,
                nonce: 0,
            };
            let mut block = Block {
                header,
                txdata: vec![coinbase],
            };
            block.header.merkle_root = block.compute_merkle_root().unwrap();
            let target = Target::from_compact(bits);
            for nonce in 0..u32::MAX {
                block.header.nonce = nonce;
                if block.header.validate_pow(target).is_ok() {
                    break;
                }
            }
            block
        }

        let lose = mine(gen, 1_700_000_100, 1);
        let mut win = mine(gen, 1_700_000_101, 1);
        if win.block_hash() == lose.block_hash() {
            let target = Target::from_compact(win.header.bits);
            for nonce in 0..u32::MAX {
                win.header.nonce = nonce;
                if win.header.validate_pow(target).is_ok() && win.block_hash() != lose.block_hash()
                {
                    break;
                }
            }
        }
        hub.accept_block(lose.clone()).unwrap();
        hub.ensure_header(&win.header).unwrap();
        let ext = mine(win.block_hash(), 1_700_000_200, 2);
        hub.ensure_header(&ext.header).unwrap();

        let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
        seed_work_path_from_store(&mut st, &hub);
        assert_eq!(
            hub.tip_hash(),
            Some(gen),
            "must disconnect the loser so the winner is a linear tip+1"
        );
        assert_eq!(hub.tip_height(), Some(0));
        assert_eq!(st.height_to_hash.get(&1), Some(&win.block_hash()));
        assert_eq!(st.height_to_hash.get(&2), Some(&ext.block_hash()));
        assert!(st.ordered_set.contains(&win.block_hash()));
        assert!(st.ordered_set.contains(&ext.block_hash()));
        assert!(
            st.reorg.need_getdata().is_empty(),
            "winner is above the new tip — no side-channel gather; need={:?}",
            st.reorg.need_getdata()
        );

        assert_eq!(hub.query.lookup_taken_hi(), Some(0));
        let tips = work_path_tips(&st);
        assert!(
            tips.contains(&ext.block_hash()) || tips.contains(&win.block_hash()),
            "locator tips must include the winning path"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
