//! Cluster linearization: Core's ancestor-set candidate search, then
//! `PostLinearize`, then `ChunkLinearization` (`src/cluster_linearize.h`).
//!
//! Core v31 runs spanning-forest linearization (SFL) under a cost budget and
//! usually reaches the optimal fee-size diagram. This module does not port
//! SFL. It runs the pre-SFL pipeline instead:
//!
//! 1. Repeatedly take the remaining transaction whose ancestor set (within
//!    what is left) has the highest feerate, and append that whole set. A
//!    low or negative fee parent rides with the child that pays for it.
//! 2. `PostLinearize`: one backward and one forward merge/swap pass. Chunks
//!    come out connected, and a tree-shaped cluster (every tx has at most one
//!    parent, or at most one child) is optimal.
//! 3. Chunk with Core's rule: a later group joins the chunk before it only
//!    at a **strictly** higher feerate, so equal-feerate groups stay apart.
//! 4. Emit in Core's `GetLinearization` order: chunks by feerate, and inside
//!    a chunk each transaction by its own feerate, both subject to topology.
//!
//! The result is optimal when each best chunk is an ancestor set or a union
//! the passes above merge (CPFP, chains, trees). A cluster whose best chunk
//! is a union of overlapping ancestor sets can still get a worse diagram than
//! Core. Against a brute-force optimum on random clusters of up to 16
//! transactions, under 1% of transactions got a different chunk feerate.
//!
//! Cost: every step is a bitset walk over the cluster, so one linearization
//! is O(n²) word operations plus O(n²) feerate compares for `n` members (n is
//! at most `-limitclustercount`). The graph reruns this on every cluster it
//! touches, so it trades optimality on rare shapes for a bound that does not
//! depend on the fee values.

use std::cmp::Ordering;

/// Fee and size of a set, compared by feerate (Core `FeeFrac`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FeeFrac {
    pub fee: i128,
    pub size: u64,
}

impl FeeFrac {
    pub fn new(fee: i64, size: u64) -> Self {
        Self {
            fee: i128::from(fee),
            size,
        }
    }

    fn cross(&self, other: &Self) -> (i128, i128) {
        (
            self.fee.saturating_mul(i128::from(other.size)),
            other.fee.saturating_mul(i128::from(self.size)),
        )
    }

    /// Core `operator>>`: strictly higher feerate. An empty set is neither
    /// higher nor lower than anything.
    pub fn higher_rate(&self, other: &Self) -> bool {
        let (a, b) = self.cross(other);
        a > b
    }

    /// Core `operator<=>`: feerate first, then the smaller size wins a tie.
    pub fn rank(&self, other: &Self) -> Ordering {
        let (a, b) = self.cross(other);
        a.cmp(&b).then_with(|| other.size.cmp(&self.size))
    }

    fn add(&mut self, other: &Self) {
        self.fee = self.fee.saturating_add(other.fee);
        self.size = self.size.saturating_add(other.size);
    }

    fn sub(&mut self, other: &Self) {
        self.fee = self.fee.saturating_sub(other.fee);
        self.size = self.size.saturating_sub(other.size);
    }
}

/// Fixed-width bitset over cluster positions.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TxSet(Vec<u64>);

impl TxSet {
    fn empty(n: usize) -> Self {
        Self(vec![0; n.div_ceil(64)])
    }

    fn singleton(n: usize, i: usize) -> Self {
        let mut s = Self::empty(n);
        s.insert(i);
        s
    }

    fn insert(&mut self, i: usize) {
        self.0[i / 64] |= 1u64 << (i % 64);
    }

    fn union_with(&mut self, other: &Self) {
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a |= *b;
        }
    }

    fn subtract(&mut self, other: &Self) {
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a &= !*b;
        }
    }

    fn intersection(&self, other: &Self) -> Self {
        Self(self.0.iter().zip(&other.0).map(|(a, b)| a & b).collect())
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.0.iter().zip(&other.0).any(|(a, b)| a & b != 0)
    }

    fn is_empty(&self) -> bool {
        self.0.iter().all(|w| *w == 0)
    }

    fn is_subset(&self, other: &Self) -> bool {
        self.0.iter().zip(&other.0).all(|(a, b)| a & !b == 0)
    }

    fn count(&self) -> u32 {
        self.0.iter().map(|w| w.count_ones()).sum()
    }

    fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.0.iter().enumerate().flat_map(|(wi, &w)| {
            let mut bits = w;
            std::iter::from_fn(move || {
                if bits == 0 {
                    return None;
                }
                let b = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                Some(wi * 64 + b)
            })
        })
    }
}

/// One cluster's dependency graph (Core `DepGraph`). Positions are the
/// caller's member order, which is also the tie-break order.
#[derive(Debug, Clone)]
pub struct DepGraph {
    feerate: Vec<FeeFrac>,
    ancestors: Vec<TxSet>,
    descendants: Vec<TxSet>,
}

impl DepGraph {
    /// `parents[i]` are positions `i` spends; anything outside `0..n` is
    /// ignored. A dependency cycle cannot come from real transactions; its
    /// members get only the ancestors reached before the cycle.
    pub fn new(feerate: Vec<FeeFrac>, parents: &[Vec<usize>]) -> Self {
        let n = feerate.len();
        let mut ancestors: Vec<TxSet> = (0..n).map(|i| TxSet::singleton(n, i)).collect();
        let mut pending: Vec<usize> = (0..n)
            .map(|i| parents[i].iter().filter(|&&p| p < n && p != i).count())
            .collect();
        let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (i, ps) in parents.iter().enumerate().take(n) {
            for &p in ps.iter().filter(|&&p| p < n && p != i) {
                children[p].push(i);
            }
        }
        let mut ready: Vec<usize> = (0..n).filter(|&i| pending[i] == 0).collect();
        while let Some(p) = ready.pop() {
            for &c in &children[p] {
                let anc = ancestors[p].clone();
                ancestors[c].union_with(&anc);
                pending[c] -= 1;
                if pending[c] == 0 {
                    ready.push(c);
                }
            }
        }
        let mut descendants: Vec<TxSet> = (0..n).map(|_| TxSet::empty(n)).collect();
        for (i, anc) in ancestors.iter().enumerate() {
            for a in anc.iter() {
                descendants[a].insert(i);
            }
        }
        Self {
            feerate,
            ancestors,
            descendants,
        }
    }

    fn len(&self) -> usize {
        self.feerate.len()
    }

    fn set_feerate(&self, set: &TxSet) -> FeeFrac {
        let mut f = FeeFrac::default();
        for i in set.iter() {
            f.add(&self.feerate[i]);
        }
        f
    }

    /// `set` in a topological order: fewer ancestors first, then position.
    fn append_topo(&self, set: &TxSet, out: &mut Vec<usize>) {
        let start = out.len();
        out.extend(set.iter());
        out[start..].sort_by_key(|&i| (self.ancestors[i].count(), i));
    }

    /// Core-style linearization: ancestor-set candidates, then
    /// [`post_linearize`](Self::post_linearize).
    pub fn linearize(&self) -> Vec<usize> {
        let n = self.len();
        let mut todo = TxSet::empty(n);
        for i in 0..n {
            todo.insert(i);
        }
        let mut anc_rate: Vec<FeeFrac> =
            self.ancestors.iter().map(|a| self.set_feerate(a)).collect();
        let mut out = Vec::with_capacity(n);
        while !todo.is_empty() {
            let Some(best) = todo
                .iter()
                .reduce(|b, i| match anc_rate[i].rank(&anc_rate[b]) {
                    Ordering::Greater => i,
                    _ => b,
                })
            else {
                break;
            };
            let pick = self.ancestors[best].intersection(&todo);
            for t in pick.iter() {
                let fr = self.feerate[t];
                for d in self.descendants[t].intersection(&todo).iter() {
                    anc_rate[d].sub(&fr);
                }
            }
            todo.subtract(&pick);
            self.append_topo(&pick, &mut out);
        }
        self.post_linearize(&mut out);
        self.output_order(&out)
    }

    /// Core `GetLinearization` output order for the chunks of `lin`: chunks
    /// by topology, then higher chunk feerate, smaller size, lower highest
    /// position; inside a chunk, transactions by topology, then higher own
    /// feerate, smaller size, lower position.
    fn output_order(&self, lin: &[usize]) -> Vec<usize> {
        let n = self.len();
        let in_order: Vec<FeeFrac> = lin.iter().map(|&i| self.feerate[i]).collect();
        let mut chunks: Vec<(TxSet, FeeFrac, usize)> = Vec::new();
        let mut start = 0;
        for len in chunk_lengths(&in_order) {
            let mut set = TxSet::empty(n);
            for &i in &lin[start..start + len] {
                set.insert(i);
            }
            let top = lin[start..start + len].iter().copied().max().unwrap_or(0);
            chunks.push((set.clone(), self.set_feerate(&set), top));
            start += len;
        }
        let mut done = TxSet::empty(n);
        let mut out = Vec::with_capacity(lin.len());
        while !chunks.is_empty() {
            let ready = |c: &(TxSet, FeeFrac, usize)| {
                c.0.iter().all(|t| {
                    let mut outside = self.ancestors[t].clone();
                    outside.subtract(&c.0);
                    outside.is_subset(&done)
                })
            };
            let Some(pick) = (0..chunks.len())
                .filter(|&k| ready(&chunks[k]))
                .reduce(|b, k| {
                    let (cb, ck) = (&chunks[b], &chunks[k]);
                    match ck.1.rank(&cb.1).then_with(|| cb.2.cmp(&ck.2)) {
                        Ordering::Greater => k,
                        _ => b,
                    }
                })
            else {
                break;
            };
            let (mut left, _, _) = chunks.remove(pick);
            while let Some(t) = left
                .iter()
                .filter(|&t| {
                    let mut need = self.ancestors[t].clone();
                    need.subtract(&TxSet::singleton(n, t));
                    need.is_subset(&done)
                })
                .reduce(|b, t| match self.feerate[t].rank(&self.feerate[b]) {
                    Ordering::Greater => t,
                    _ => b,
                })
            {
                left.subtract(&TxSet::singleton(n, t));
                done.insert(t);
                out.push(t);
            }
        }
        out
    }

    /// Core `PostLinearize`: a backward then a forward merge/swap pass. Each
    /// pass is equal or better in the diagram sense.
    pub fn post_linearize(&self, lin: &mut [usize]) {
        let n = self.len();
        for pass in 0..2 {
            let rev = pass == 0;
            let mut groups: Vec<Group> = Vec::with_capacity(lin.len());
            for k in 0..lin.len() {
                let idx = lin[if rev { lin.len() - 1 - k } else { k }];
                let mut feerate = self.feerate[idx];
                if rev {
                    feerate.fee = -feerate.fee;
                }
                let mut cur = Group {
                    txs: vec![idx],
                    set: TxSet::singleton(n, idx),
                    deps: if rev {
                        self.descendants[idx].clone()
                    } else {
                        self.ancestors[idx].clone()
                    },
                    feerate,
                };
                let mut at = groups.len();
                while at > 0 && cur.feerate.higher_rate(&groups[at - 1].feerate) {
                    // Merge a group `cur` depends on; otherwise `cur` moves
                    // in front of it.
                    if cur.deps.overlaps(&groups[at - 1].set) {
                        let prev = groups.remove(at - 1);
                        cur.absorb_before(prev);
                    }
                    at -= 1;
                }
                groups.insert(at, cur);
            }
            let flat: Vec<usize> = groups.into_iter().flat_map(|g| g.txs).collect();
            for (k, idx) in flat.into_iter().enumerate() {
                lin[if rev { lin.len() - 1 - k } else { k }] = idx;
            }
        }
    }
}

/// Core `ChunkLinearization` over feerates in linearization order: a group
/// joins the chunk before it only at a strictly higher feerate. Returns the
/// chunk lengths in order.
pub fn chunk_lengths(in_order: &[FeeFrac]) -> Vec<usize> {
    let mut chunks: Vec<(FeeFrac, usize)> = Vec::new();
    for fr in in_order {
        let mut cur = (*fr, 1usize);
        while let Some(&(last, len)) = chunks.last() {
            if !cur.0.higher_rate(&last) {
                break;
            }
            chunks.pop();
            cur.0.add(&last);
            cur.1 += len;
        }
        chunks.push(cur);
    }
    chunks.into_iter().map(|(_, len)| len).collect()
}

/// One `PostLinearize` group: transactions in pass order, their deps
/// (ancestors forward, descendants backward) and their feerate (fee negated
/// on the backward pass).
struct Group {
    txs: Vec<usize>,
    set: TxSet,
    deps: TxSet,
    feerate: FeeFrac,
}

impl Group {
    fn absorb_before(&mut self, prev: Group) {
        let mut txs = prev.txs;
        txs.append(&mut self.txs);
        self.txs = txs;
        self.set.union_with(&prev.set);
        self.deps.union_with(&prev.deps);
        self.feerate.add(&prev.feerate);
    }
}
