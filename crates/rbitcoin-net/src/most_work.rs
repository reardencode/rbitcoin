//! Most-work ranking helpers (header work sums, LCA on a parent graph).
//!
//! Layer 1 of most-work selection (`docs/architecture.md`): candidate
//! ranking uses header work only. Apply/validation is separate
//! (`ChainHub::accept_branch`).

use bitcoin::Work;

/// Header work could not be summed or read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkOverflow;

/// Sum header work values (Bitcoin most-work accumulation).
/// Overflow is an error. Addition is byte-wise so a full `Work` does not
/// hit rust-bitcoin's debug overflow assert.
pub fn sum_work(iter: impl Iterator<Item = Work>) -> Result<Work, WorkOverflow> {
    let mut acc: Option<Work> = None;
    for w in iter {
        acc = Some(match acc {
            None => w,
            Some(a) => checked_add_work(a, w)?,
        });
    }
    Ok(acc.unwrap_or_else(|| Work::from_be_bytes([0u8; 32])))
}

fn checked_add_work(a: Work, b: Work) -> Result<Work, WorkOverflow> {
    let mut out = a.to_be_bytes();
    let rhs = b.to_be_bytes();
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let s = u16::from(out[i]) + u16::from(rhs[i]) + carry;
        out[i] = s as u8;
        carry = s >> 8;
    }
    if carry != 0 {
        Err(WorkOverflow)
    } else {
        Ok(Work::from_be_bytes(out))
    }
}

/// `Header::work` panics in debug when `bits` is a zero target.
pub fn header_work_checked(header: &bitcoin::block::Header) -> Result<Work, WorkOverflow> {
    if header.bits.to_consensus() == 0 {
        return Err(WorkOverflow);
    }
    let target = bitcoin::Target::from_compact(header.bits);
    if target.to_be_bytes() == [0u8; 32] {
        return Err(WorkOverflow);
    }
    Ok(header.work())
}

/// Strictly more work (Bitcoin most-work rule).
#[inline]
pub fn work_better(new: Work, old: Work) -> bool {
    new > old
}

/// Process-local set of invalid block / candidate-tip hashes after failed apply.
#[derive(Debug, Default, Clone)]
pub struct InvalidHashSet {
    hashes: std::collections::HashSet<[u8; 32]>,
}

impl InvalidHashSet {
    /// The set does not grow past this. A hash that does not fit is still
    /// invalid for the decision that just failed it; later lookups may miss it.
    pub const CAP: usize = 4_096;

    pub fn mark(&mut self, hash: [u8; 32]) {
        if self.hashes.len() >= Self::CAP && !self.hashes.contains(&hash) {
            return;
        }
        self.hashes.insert(hash);
    }

    pub fn iter(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.hashes.iter().copied()
    }

    pub fn contains(&self, hash: [u8; 32]) -> bool {
        self.hashes.contains(&hash)
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn w(n: u8) -> Work {
        let mut b = [0u8; 32];
        b[31] = n;
        Work::from_be_bytes(b)
    }

    #[test]
    fn sum_work_and_work_better() {
        let z = Work::from_be_bytes([0u8; 32]);
        assert_eq!(sum_work(std::iter::empty()).unwrap(), z);
        assert_eq!(sum_work([w(1)].into_iter()).unwrap(), w(1));
        let mut ff = [0u8; 32];
        ff[31] = 0xff;
        let mut carried = [0u8; 32];
        carried[30] = 1;
        assert_eq!(
            sum_work([Work::from_be_bytes(ff), w(1)].into_iter()).unwrap(),
            Work::from_be_bytes(carried),
            "0xff + 1 carries into the next byte"
        );
        let max = Work::from_be_bytes([0xff; 32]);
        assert_eq!(sum_work([max, w(1)].into_iter()), Err(WorkOverflow));
        let mut zero_bits = bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(1),
            prev_blockhash: bitcoin::BlockHash::from_byte_array([0u8; 32]),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time: 0,
            bits: bitcoin::CompactTarget::from_consensus(0),
            nonce: 0,
        };
        assert!(header_work_checked(&zero_bits).is_err());
        zero_bits.bits = bitcoin::CompactTarget::from_consensus(0x207f_ffff);
        assert!(header_work_checked(&zero_bits).is_ok());
        assert!(work_better(w(2), w(1)));
        assert!(!work_better(w(1), w(2)));
        assert!(!work_better(w(1), w(1)));
    }

    #[test]
    fn invalid_hash_set_stops_at_the_cap() {
        let mut set = InvalidHashSet::default();
        for i in 0..InvalidHashSet::CAP {
            let mut h = [0u8; 32];
            h[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            set.mark(h);
        }
        let extra = [0xff; 32];
        set.mark(extra);
        assert!(!set.contains(extra), "past the cap is not stored");
        let mut first = [0u8; 32];
        first[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert!(set.contains(first), "the set is not cleared");
    }

    #[test]
    fn invalid_hash_set_marks_and_skips() {
        let mut set = InvalidHashSet::default();
        assert!(set.is_empty());
        let h = [0xab; 32];
        set.mark(h);
        assert!(set.contains(h));
        assert!(!set.is_empty());
        set.mark([0x02; 32]);
        assert!(set.contains([0x02; 32]));
        assert!(!set.contains([0x00; 32]));
    }
}
