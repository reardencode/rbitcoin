use bitcoin::hashes::Hash;

/// Milestone policy (assumevalid-style): skip **script/sig** checks at/below height.
///
/// Prevout existence, double-spend, maturity, and fees are always checked on
/// contiguous tip confirm. Only pure-Rust script/signature verification is gated.
///
/// A height-only milestone (`anchor: None`) is the explicit `--milestone HEIGHT`
/// speed switch. The mainnet and testnet3 defaults also carry
/// [`MilestoneAnchor`]: skip only when this block and the anchor hash are the
/// header-path occupants at their heights and best-header work meets
/// `min_work_be`. Lookups are the caller's; this type does not walk ancestors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MilestoneAnchor {
    pub hash: bitcoin::BlockHash,
    /// 32-byte big-endian chain work floor (Core `nMinimumChainWork` shape).
    pub min_work_be: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Milestone {
    pub height: u32,
    pub anchor: Option<MilestoneAnchor>,
}

impl Milestone {
    pub const NONE: Milestone = Milestone {
        height: 0,
        anchor: None,
    };

    /// Explicit height skip. No ancestor or min-work gate.
    pub const fn height(height: u32) -> Self {
        Self {
            height,
            anchor: None,
        }
    }

    /// Height-only skip. An anchored milestone never skips on height alone.
    pub fn skips_scripts_at(self, height: u32) -> bool {
        self.anchor.is_none() && self.height > 0 && height <= self.height
    }

    /// Script skip for `block` at `height`.
    ///
    /// `header_at` and `best_work_be` are O(1) views of the header path (or
    /// the confirmed chain). A missing lookup does not skip.
    pub fn skips_scripts(
        self,
        height: u32,
        block: &[u8; 32],
        header_at: impl Fn(u32) -> Option<[u8; 32]>,
        best_work_be: Option<[u8; 32]>,
    ) -> bool {
        if self.height == 0 || height > self.height {
            return false;
        }
        let Some(anchor) = self.anchor else {
            return true;
        };
        if header_at(height).as_ref() != Some(block) {
            return false;
        }
        if header_at(self.height).as_ref() != Some(anchor.hash.as_byte_array()) {
            return false;
        }
        match best_work_be {
            Some(w) => w >= anchor.min_work_be,
            None => false,
        }
    }
}

/// Confirm-path gate. Notes `milestone_gate_ns` (`ibd: perf_dbg milestone_us`).
pub(crate) fn skips_on_query(
    milestone: Milestone,
    query: &rbitcoin_query::Query,
    height: u32,
    block: &[u8; 32],
) -> bool {
    let t = std::time::Instant::now();
    let skip = milestone.skips_scripts(
        height,
        block,
        |h| query.milestone_header_at(h),
        query.milestone_best_work_be(),
    );
    rbitcoin_query::note_confirm(
        &query.confirm_stats().milestone_gate_ns,
        t.elapsed().as_nanos() as u64,
    );
    skip
}

pub(crate) fn check_scripts(
    milestone: Milestone,
    query: &rbitcoin_query::Query,
    height: u32,
    block: &[u8; 32],
) -> bool {
    !skips_on_query(milestone, query, height, block)
}

impl Default for Milestone {
    fn default() -> Self {
        Self::NONE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn anchor(hash: [u8; 32], min_work_be: [u8; 32]) -> Milestone {
        Milestone {
            height: 100,
            anchor: Some(MilestoneAnchor {
                hash: bitcoin::BlockHash::from_byte_array(hash),
                min_work_be,
            }),
        }
    }

    #[test]
    fn none_and_default_never_skip() {
        assert_eq!(Milestone::default(), Milestone::NONE);
        assert!(!Milestone::NONE.skips_scripts_at(0));
        assert!(!Milestone::NONE.skips_scripts_at(1_000_000));
        assert!(!Milestone::NONE.skips_scripts(0, &[0; 32], |_| None, None));
        assert!(!Milestone::NONE.skips_scripts(1, &[0; 32], |_| None, None));
    }

    #[test]
    fn height_gate_skips_at_and_below() {
        let m = Milestone::height(100);
        assert!(m.skips_scripts_at(1));
        assert!(m.skips_scripts_at(100));
        assert!(!m.skips_scripts_at(101));
        assert!(m.skips_scripts(50, &[9; 32], |_| None, None));
    }

    #[test]
    fn low_work_fork_does_not_skip_even_at_the_milestone_height() {
        let anchor_hash = [0x11u8; 32];
        let fork = [0x22u8; 32];
        let honest = [0x33u8; 32];
        let mut min = [0u8; 32];
        min[1] = 0x10;
        let m = anchor(anchor_hash, min);
        assert!(!m.skips_scripts_at(50), "anchor is not a bare height skip");

        let mut headers = std::collections::HashMap::new();
        headers.insert(50u32, fork);
        let low = {
            let mut w = [0u8; 32];
            w[1] = 0x01;
            w
        };
        let enough = {
            let mut w = [0u8; 32];
            w[1] = 0x10;
            w
        };
        assert!(!m.skips_scripts(50, &fork, |h| headers.get(&h).copied(), Some(enough)));
        headers.insert(100, anchor_hash);
        headers.insert(50, honest);
        assert!(
            !m.skips_scripts(50, &fork, |h| headers.get(&h).copied(), Some(enough)),
            "a different hash at the same height is not the anchor's ancestor"
        );
        assert!(!m.skips_scripts(50, &honest, |h| headers.get(&h).copied(), Some(low)));
        assert!(!m.skips_scripts(50, &honest, |h| headers.get(&h).copied(), None));
        assert!(m.skips_scripts(50, &honest, |h| headers.get(&h).copied(), Some(enough)));
        assert!(
            m.skips_scripts(
                100,
                &anchor_hash,
                |h| headers.get(&h).copied(),
                Some(enough)
            ),
            "the anchor block itself is buried"
        );
        let above = [0x44u8; 32];
        headers.insert(101, above);
        assert!(!m.skips_scripts(101, &above, |h| headers.get(&h).copied(), Some(enough)));
    }
}
