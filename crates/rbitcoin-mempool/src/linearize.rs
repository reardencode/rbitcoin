//! Cluster linearization by ancestor-set feerate (Core's pre-SFL
//! `AncestorCandidateFinder`, `src/cluster_linearize.h`).
//!
//! Repeatedly take the remaining transaction whose ancestor set (within what
//! is left) has the highest feerate, and append that whole set. A low or
//! negative fee parent rides with the child that pays for it, ahead of a
//! sibling that only beats the parent on its own feerate.
//!
//! Cost: every step is a bitset walk over the cluster, so one linearization
//! is O(n²) word operations plus O(n²) feerate compares for `n` members (n is
//! at most `-limitclustercount`). The graph reruns this on every cluster it
//! touches, so the bound must not depend on the fee values.

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

    fn is_empty(&self) -> bool {
        self.0.iter().all(|w| *w == 0)
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

    /// Ancestor-set candidate linearization.
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
        out
    }
}
