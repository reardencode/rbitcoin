//! Inbound peer eviction (Core `SelectNodeToEvict` / `AttemptToEvictConnection`).
//!
//! When inbound slots are full, accept a new peer only after disconnecting one
//! unprotected inbound. Protection mirrors Core: netgroup, recent blocks, recent
//! txs, lowest min-ping.

/// One inbound session considered for eviction.
#[derive(Clone, Debug)]
pub struct InboundEvictCandidate {
    pub id: u64,
    pub connected_at: u64,
    pub min_ping: Option<f64>,
    pub last_block: u64,
    pub last_tx: u64,
    pub netgroup: u64,
    pub noban: bool,
}

const PROTECT_NETGROUP: usize = 4;
const PROTECT_BLOCKS: usize = 4;
const PROTECT_TXS: usize = 4;
const PROTECT_MINPING: usize = 8;
/// Longest-connected inbound peers kept when slots are full.
const PROTECT_LONGEST: usize = 8;

/// Pick one inbound id to disconnect, or `None` if every candidate is protected.
pub fn select_inbound_eviction(mut cands: Vec<InboundEvictCandidate>) -> Option<u64> {
    cands.retain(|c| !c.noban);
    if cands.is_empty() {
        return None;
    }

    protect_by_netgroup(&mut cands, PROTECT_NETGROUP);
    if cands.is_empty() {
        return None;
    }

    cands.sort_by(|a, b| {
        b.last_block
            .cmp(&a.last_block)
            .then_with(|| a.id.cmp(&b.id))
    });
    remove_first_k(&mut cands, PROTECT_BLOCKS);
    if cands.is_empty() {
        return None;
    }

    cands.sort_by(|a, b| b.last_tx.cmp(&a.last_tx).then_with(|| a.id.cmp(&b.id)));
    remove_first_k(&mut cands, PROTECT_TXS);
    if cands.is_empty() {
        return None;
    }

    cands.sort_by(|a, b| {
        ping_key(a.min_ping)
            .partial_cmp(&ping_key(b.min_ping))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.id.cmp(&b.id))
    });
    remove_first_k(&mut cands, PROTECT_MINPING);
    if cands.is_empty() {
        return None;
    }

    // A share of the longest-connected peers stays. Evicting them is how a
    // new inbound replaces the peers that have been useful the longest.
    cands.sort_by(|a, b| {
        a.connected_at
            .cmp(&b.connected_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    remove_first_k(&mut cands, PROTECT_LONGEST);
    if cands.is_empty() {
        return None;
    }

    // Newest peer in the largest netgroup. Group ids are the integers stored
    // at accept; this compares those integers and does not read asmap.
    let mut counts = std::collections::HashMap::<u64, usize>::new();
    for c in &cands {
        *counts.entry(c.netgroup).or_insert(0) += 1;
    }
    let (group, _) = counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
        .expect("at least one candidate");
    cands
        .iter()
        .filter(|c| c.netgroup == group)
        .max_by(|a, b| {
            a.connected_at
                .cmp(&b.connected_at)
                .then_with(|| a.id.cmp(&b.id))
        })
        .map(|c| c.id)
}

fn ping_key(min_ping: Option<f64>) -> f64 {
    min_ping.unwrap_or(f64::MAX)
}

fn remove_first_k(cands: &mut Vec<InboundEvictCandidate>, k: usize) {
    let n = k.min(cands.len());
    cands.drain(0..n);
}

/// Protect up to `k` peers from the largest keyed netgroups (Core netgroup protect).
fn protect_by_netgroup(cands: &mut Vec<InboundEvictCandidate>, k: usize) {
    if k == 0 || cands.is_empty() {
        return;
    }
    use std::collections::HashMap;
    let mut counts: HashMap<u64, usize> = HashMap::new();
    for c in cands.iter() {
        *counts.entry(c.netgroup).or_insert(0) += 1;
    }
    let mut groups: Vec<(u64, usize)> = counts.into_iter().collect();
    groups.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut protect_ids = Vec::new();
    for (group, _) in groups {
        if protect_ids.len() >= k {
            break;
        }
        if let Some(c) = cands
            .iter()
            .filter(|c| c.netgroup == group)
            .min_by_key(|c| c.id)
        {
            protect_ids.push(c.id);
        }
    }
    cands.retain(|c| !protect_ids.contains(&c.id));
}

/// Stable netgroup key for eviction (IPv4 `/16`, IPv6 `/32`; no asmap).
pub fn eviction_netgroup(addr: std::net::SocketAddr) -> u64 {
    crate::netgroup::netgroup(addr, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(
        id: u64,
        connected_at: u64,
        min_ping: Option<f64>,
        last_block: u64,
        last_tx: u64,
    ) -> InboundEvictCandidate {
        InboundEvictCandidate {
            id,
            connected_at,
            min_ping,
            last_block,
            last_tx,
            netgroup: 1,
            noban: false,
        }
    }

    #[test]
    fn eviction_drops_the_newest_in_the_largest_netgroup() {
        // Low ids are one-peer groups with a better ping, so the block, tx,
        // ping, and netgroup protects consume them. The interesting peers are
        // a size-3 group and one newer peer alone in another group.
        let mut cands = Vec::new();
        for i in 1..=40 {
            cands.push(InboundEvictCandidate {
                id: i,
                connected_at: 1,
                min_ping: Some(0.01),
                last_block: 0,
                last_tx: 0,
                netgroup: 1_000 + i,
                noban: false,
            });
        }
        cands.push(InboundEvictCandidate {
            id: 100,
            connected_at: 10,
            min_ping: Some(1.0),
            last_block: 0,
            last_tx: 0,
            netgroup: 7,
            noban: false,
        });
        cands.push(InboundEvictCandidate {
            id: 101,
            connected_at: 50,
            min_ping: Some(1.0),
            last_block: 0,
            last_tx: 0,
            netgroup: 7,
            noban: false,
        });
        cands.push(InboundEvictCandidate {
            id: 102,
            connected_at: 200,
            min_ping: Some(1.0),
            last_block: 0,
            last_tx: 0,
            netgroup: 7,
            noban: false,
        });
        cands.push(InboundEvictCandidate {
            id: 103,
            connected_at: 500,
            min_ping: Some(1.0),
            last_block: 0,
            last_tx: 0,
            netgroup: 9_000,
            noban: false,
        });
        let victim = select_inbound_eviction(cands).expect("one inbound to evict");
        assert_ne!(victim, 101, "the oldest peer in the largest group stays");
        assert_ne!(victim, 103, "a newer peer in a smaller group stays");
        assert_eq!(victim, 102, "evict the newest peer in the largest netgroup");
    }

    #[test]
    fn eviction_protects_block_tx_ping_and_netgroup() {
        // 4 block + 5 slow + 4 tx + 8 fast = 21; after protects, one slow remains.
        let mut cands = Vec::new();
        for i in 0..4 {
            cands.push(cand(i, 100 + i, Some(0.05), 1000 + i, 0));
        }
        for i in 4..9 {
            cands.push(cand(i, 200 + i, Some(0.5), 0, 0));
        }
        for i in 9..13 {
            cands.push(cand(i, 300 + i, Some(0.05), 0, 1000 + i));
        }
        for i in 13..21 {
            cands.push(cand(i, 400 + i, Some(0.01), 0, 0));
        }
        assert!(
            select_inbound_eviction(cands).is_none(),
            "block, tx, ping, netgroup, and longest-connected protects cover this set"
        );
    }

    #[test]
    fn noban_never_evicted_alone() {
        let cands = vec![InboundEvictCandidate {
            id: 7,
            connected_at: 1,
            min_ping: Some(9.0),
            last_block: 0,
            last_tx: 0,
            netgroup: 1,
            noban: true,
        }];
        assert!(select_inbound_eviction(cands).is_none());
    }

    #[test]
    fn maxconnections_shaped_protect_count() {
        // Fewer than protect budget → nothing to evict.
        let cands: Vec<_> = (0..8).map(|i| cand(i, i, Some(0.1), i, i)).collect();
        assert!(select_inbound_eviction(cands).is_none());
    }

    #[test]
    fn eviction_netgroup_ipv4_slash16() {
        let a: std::net::SocketAddr = "1.2.3.4:1".parse().unwrap();
        let b: std::net::SocketAddr = "1.2.9.9:1".parse().unwrap();
        let c: std::net::SocketAddr = "1.3.0.1:1".parse().unwrap();
        assert_eq!(eviction_netgroup(a), eviction_netgroup(b));
        assert_ne!(eviction_netgroup(a), eviction_netgroup(c));
    }
}
