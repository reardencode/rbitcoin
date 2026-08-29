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

    cands.sort_by(|a, b| b.last_block.cmp(&a.last_block).then_with(|| a.id.cmp(&b.id)));
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

    // Prefer the longest-connected remaining peer (stable id tie-break).
    cands.sort_by(|a, b| a.connected_at.cmp(&b.connected_at).then_with(|| a.id.cmp(&b.id)));
    Some(cands[0].id)
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
        if let Some(c) = cands.iter().filter(|c| c.netgroup == group).min_by_key(|c| c.id) {
            protect_ids.push(c.id);
        }
    }
    cands.retain(|c| !protect_ids.contains(&c.id));
}

/// Stable netgroup key for eviction (IPv4 /24, else full IP hash).
pub fn eviction_netgroup(addr: std::net::SocketAddr) -> u64 {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            u64::from(o[0]) << 16 | u64::from(o[1]) << 8 | u64::from(o[2])
        }
        std::net::IpAddr::V6(v6) => {
            let o = v6.octets();
            u64::from_be_bytes([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]])
        }
    }
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
        let victim = select_inbound_eviction(cands).expect("one unprotected slow");
        assert!((4..9).contains(&victim), "victim={victim}");
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
}
