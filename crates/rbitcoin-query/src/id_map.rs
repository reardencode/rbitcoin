//! Txid / outpoint identity hashers and the wave `txid → (fk, body_range)` map.

use rbitcoin_primitives::Fk;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

/// Identity hasher for `[u8; 32]` txids (already uniform). `finish()` is the
/// first 8 bytes; equality still compares the full key.
#[derive(Default, Clone, Copy)]
pub struct TxidHasher(u64);

impl Hasher for TxidHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        if bytes.len() >= 8 {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[..8]);
            self.0 = u64::from_le_bytes(raw);
        } else {
            self.0 = 0;
            for (i, &b) in bytes.iter().enumerate() {
                self.0 |= u64::from(b) << (8 * i);
            }
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

/// Mixes every `write` so `(txid, vout)` keys stay distinct.
///
/// [`TxidHasher`] overwrites `self.0` per write — using it on an outpoint
/// would drop the txid hash when the vout bytes arrive.
#[derive(Default, Clone, Copy)]
pub struct OutPointHasher(u64);

impl Hasher for OutPointHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

/// `(txid, vout)` set that folds every hasher write (see [`OutPointHasher`]).
pub type OutPointSet =
    std::collections::HashSet<([u8; 32], u32), BuildHasherDefault<OutPointHasher>>;

/// Immutable `txid → (create_fk, body_range)` for one resolve wave.
pub type IdMap = HashMap<[u8; 32], (Fk, (u64, u64)), BuildHasherDefault<TxidHasher>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txid_hasher_uses_first_8_bytes() {
        let mut h = TxidHasher::default();
        let mut t = [0u8; 32];
        t[..8].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        t[8] = 0xff;
        h.write(&t);
        assert_eq!(h.finish(), 0x0102_0304_0506_0708);
        let mut other = [0u8; 32];
        other[..8].copy_from_slice(&t[..8]);
        other[31] = 1;
        let mut h2 = TxidHasher::default();
        h2.write(&other);
        assert_eq!(
            h2.finish(),
            h.finish(),
            "same prefix must hash equal; full-key eq still separates them"
        );
        let mut m = IdMap::default();
        m.insert(t, (Fk(1), (0, 1)));
        m.insert(other, (Fk(2), (0, 1)));
        assert_eq!(m.get(&t).map(|v| v.0), Some(Fk(1)));
        assert_eq!(m.get(&other).map(|v| v.0), Some(Fk(2)));
    }

    #[test]
    fn outpoint_hasher_mixes_vout() {
        use std::collections::HashSet;
        use std::hash::{BuildHasher, BuildHasherDefault};
        let mut prefix = [0u8; 32];
        prefix[..8].copy_from_slice(&0x1111_2222_3333_4444u64.to_le_bytes());
        let mut other = prefix;
        other[8] = 0xaa;
        let build = BuildHasherDefault::<OutPointHasher>::default();
        let hash_of = |txid: [u8; 32], vout: u32| build.hash_one((txid, vout));
        assert_ne!(
            hash_of(prefix, 0),
            hash_of(prefix, 1),
            "same txid prefix, vout 0 vs 1 must hash distinct"
        );
        assert_ne!(
            hash_of(prefix, 0),
            hash_of(other, 0),
            "different txid, same vout must hash distinct (TxidHasher overwrites with vout)"
        );
        type Set = HashSet<([u8; 32], u32), BuildHasherDefault<OutPointHasher>>;
        let mut s: Set = HashSet::with_hasher(BuildHasherDefault::default());
        assert!(s.insert((prefix, 0)));
        assert!(
            s.insert((prefix, 1)),
            "same txid prefix, vout 0 vs 1 must be distinct"
        );
        assert_eq!(s.len(), 2);
        assert!(
            s.insert((other, 0)),
            "different txid, same vout must stay distinct"
        );
        assert_eq!(s.len(), 3);
    }
}
