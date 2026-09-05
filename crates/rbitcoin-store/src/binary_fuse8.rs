//! In-tree Binary Fuse8 (8-bit fingerprints).
//!
//! Algorithm port of FastFilter binary fuse / xorf `BinaryFuse8` (MIT).
//! Field layout matches historical bincode of xorf 0.11 so on-disk v1 bodies
//! remain readable.
//!
//! References:
//! - https://arxiv.org/abs/1907.04749
//! - https://github.com/ayazhafiz/xorf (MIT)

#![allow(clippy::needless_range_loop)]

/// Immutable binary-fuse membership filter over `u64` keys.
#[derive(Debug, Clone)]
pub struct BinaryFuse8 {
    pub seed: u64,
    pub segment_length: u32,
    pub segment_length_mask: u32,
    pub segment_count_length: u32,
    pub fingerprints: Box<[u8]>,
}

#[inline]
fn splitmix64(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[inline]
fn mix64(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51_afd7_ed55_8ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    k ^= k >> 33;
    k
}

#[inline]
fn mix(key: u64, seed: u64) -> u64 {
    mix64(key.wrapping_add(seed))
}

#[inline]
fn fingerprint(hash: u64) -> u64 {
    hash ^ (hash >> 32)
}

#[inline]
fn segment_length(arity: u32, size: u32) -> u32 {
    if size == 0 {
        return 4;
    }
    match arity {
        3 => 1u32 << ((size as f64).ln() / 3.33_f64.ln() + 2.25).floor() as u32,
        _ => 65536,
    }
}

#[inline]
fn size_factor(arity: u32, size: u32) -> f64 {
    match arity {
        3 => (1.125_f64).max(0.875 + 0.25 * 1_000_000_f64.ln() / (size as f64).ln()),
        _ => 2.0,
    }
}

#[inline]
const fn hash_of_hash(
    hash: u64,
    segment_length: u32,
    segment_length_mask: u32,
    segment_count_length: u32,
) -> (u32, u32, u32) {
    let hi = ((hash as u128 * segment_count_length as u128) >> 64) as u64;
    let h0 = hi as u32;
    let mut h1 = h0 + segment_length;
    let mut h2 = h1 + segment_length;
    h1 ^= ((hash >> 18) as u32) & segment_length_mask;
    h2 ^= (hash as u32) & segment_length_mask;
    (h0, h1, h2)
}

#[inline]
const fn mod3(x: u8) -> u8 {
    if x > 2 {
        x - 3
    } else {
        x
    }
}

impl BinaryFuse8 {
    /// Build from distinct keys. Fails on construction timeout (usually dups).
    pub fn try_from_keys(keys: &[u64]) -> Result<Self, &'static str> {
        let arity = 3u32;
        let size = keys.len();
        let segment_length: u32 = segment_length(arity, size as u32).min(262_144);
        let segment_length_mask: u32 = segment_length - 1;
        let size_factor = size_factor(arity, size as u32);
        let capacity: u32 = if size > 1 {
            (size as f64 * size_factor).round() as u32
        } else {
            0
        };
        let init_segment_count = capacity.saturating_add(segment_length - 1) / segment_length;
        let (fp_array_len, segment_count) = {
            let array_len = init_segment_count * segment_length;
            let proposed = array_len.saturating_add(segment_length - 1) / segment_length;
            let segment_count = if proposed < arity {
                1
            } else {
                proposed - (arity - 1)
            };
            let array_len = (segment_count + arity - 1) * segment_length;
            (array_len as usize, segment_count)
        };
        let segment_count_length = segment_count * segment_length;

        let mut fingerprints = vec![0u8; fp_array_len].into_boxed_slice();
        let mut rng = 1u64;
        let mut seed = splitmix64(&mut rng);
        let capacity = fingerprints.len();
        let mut alone = vec![0u32; capacity];
        let mut t2count = vec![0u8; capacity];
        let mut t2hash = vec![0u64; capacity];
        let mut reverse_h = vec![0u8; size];
        let mut reverse_order = vec![0u64; size + 1];
        if size < reverse_order.len() {
            reverse_order[size] = 1;
        }

        let mut block_bits = 1u32;
        while (1u32 << block_bits) < segment_count {
            block_bits += 1;
        }
        let start_pos_len: usize = 1 << block_bits;
        let mut start_pos = vec![0usize; start_pos_len];
        let mut h012 = [0u32; 6];
        let mut done = false;
        let mut ultimate_size = 0usize;
        const MAX_ITER: usize = 1_000;

        for _ in 0..MAX_ITER {
            for i in 0..start_pos_len {
                start_pos[i] = ((i as u64).wrapping_mul(size as u64) >> block_bits) as usize;
            }
            for &key in keys {
                let hash = mix(key, seed);
                let mut segment_index = hash >> (64 - block_bits);
                while reverse_order[start_pos[segment_index as usize]] != 0 {
                    segment_index += 1;
                    segment_index &= (1 << block_bits) - 1;
                }
                reverse_order[start_pos[segment_index as usize]] = hash;
                start_pos[segment_index as usize] += 1;
            }

            let mut error = false;
            let mut duplicates = 0usize;
            for i in 0..size {
                let hash = reverse_order[i];
                let (index1, index2, index3) = hash_of_hash(
                    hash,
                    segment_length,
                    segment_length_mask,
                    segment_count_length,
                );
                let (index1, index2, index3) = (index1 as usize, index2 as usize, index3 as usize);
                t2count[index1] = t2count[index1].wrapping_add(4);
                t2hash[index1] ^= hash;
                t2count[index2] = t2count[index2].wrapping_add(4);
                t2count[index2] ^= 1;
                t2hash[index2] ^= hash;
                t2count[index3] = t2count[index3].wrapping_add(4);
                t2count[index3] ^= 2;
                t2hash[index3] ^= hash;

                if t2hash[index1] & t2hash[index2] & t2hash[index3] == 0
                    && (((t2hash[index1] == 0) && (t2count[index1] == 8))
                        || ((t2hash[index2] == 0) && (t2count[index2] == 8))
                        || ((t2hash[index3] == 0) && (t2count[index3] == 8)))
                {
                    duplicates += 1;
                    t2count[index1] = t2count[index1].wrapping_sub(4);
                    t2hash[index1] ^= hash;
                    t2count[index2] = t2count[index2].wrapping_sub(4);
                    t2count[index2] ^= 1;
                    t2hash[index2] ^= hash;
                    t2count[index3] = t2count[index3].wrapping_sub(4);
                    t2count[index3] ^= 2;
                    t2hash[index3] ^= hash;
                }
                error = t2count[index1] < 4 || t2count[index2] < 4 || t2count[index3] < 4;
            }
            if error {
                for i in 0..size {
                    reverse_order[i] = 0;
                }
                for i in 0..capacity {
                    t2count[i] = 0;
                    t2hash[i] = 0;
                }
                seed = splitmix64(&mut rng);
                continue;
            }

            let mut qsize = 0usize;
            for i in 0..capacity {
                alone[qsize] = i as u32;
                if (t2count[i] >> 2) == 1 {
                    qsize += 1;
                }
            }
            let mut stack_size = 0usize;
            while qsize > 0 {
                qsize -= 1;
                let index = alone[qsize] as usize;
                if (t2count[index] >> 2) == 1 {
                    let hash = t2hash[index];
                    let found: u8 = t2count[index] & 3;
                    reverse_h[stack_size] = found;
                    reverse_order[stack_size] = hash;
                    stack_size += 1;

                    let (index1, index2, index3) = hash_of_hash(
                        hash,
                        segment_length,
                        segment_length_mask,
                        segment_count_length,
                    );
                    h012[1] = index2;
                    h012[2] = index3;
                    h012[3] = index1;
                    h012[4] = h012[1];

                    let other_index1 = h012[(found + 1) as usize] as usize;
                    alone[qsize] = other_index1 as u32;
                    if (t2count[other_index1] >> 2) == 2 {
                        qsize += 1;
                    }
                    t2count[other_index1] = t2count[other_index1].wrapping_sub(4);
                    t2count[other_index1] ^= mod3(found + 1);
                    t2hash[other_index1] ^= hash;

                    let other_index2 = h012[(found + 2) as usize] as usize;
                    alone[qsize] = other_index2 as u32;
                    if (t2count[other_index2] >> 2) == 2 {
                        qsize += 1;
                    }
                    t2count[other_index2] = t2count[other_index2].wrapping_sub(4);
                    t2count[other_index2] ^= mod3(found + 2);
                    t2hash[other_index2] ^= hash;
                }
            }

            if stack_size + duplicates == size {
                ultimate_size = stack_size;
                done = true;
                break;
            }

            for i in 0..size {
                reverse_order[i] = 0;
            }
            for i in 0..capacity {
                t2count[i] = 0;
                t2hash[i] = 0;
            }
            seed = splitmix64(&mut rng);
        }
        if !done {
            return Err("Failed to construct binary fuse filter.");
        }

        let size = ultimate_size;
        for i in (0..size).rev() {
            let hash = reverse_order[i];
            let xor2 = fingerprint(hash) as u8;
            let (index1, index2, index3) = hash_of_hash(
                hash,
                segment_length,
                segment_length_mask,
                segment_count_length,
            );
            let found = reverse_h[i] as usize;
            h012[0] = index1;
            h012[1] = index2;
            h012[2] = index3;
            h012[3] = h012[0];
            h012[4] = h012[1];
            fingerprints[h012[found] as usize] = xor2
                ^ fingerprints[h012[found + 1] as usize]
                ^ fingerprints[h012[found + 2] as usize];
        }

        Ok(Self {
            seed,
            segment_length,
            segment_length_mask,
            segment_count_length,
            fingerprints,
        })
    }

    #[inline]
    pub fn contains(&self, key: u64) -> bool {
        let hash = mix(key, self.seed);
        let mut f = fingerprint(hash) as u8;
        let (h0, h1, h2) = hash_of_hash(
            hash,
            self.segment_length,
            self.segment_length_mask,
            self.segment_count_length,
        );
        f ^= self.fingerprints[h0 as usize]
            ^ self.fingerprints[h1 as usize]
            ^ self.fingerprints[h2 as usize];
        f == 0
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_key_and_small_set_no_false_negatives() {
        let one = BinaryFuse8::try_from_keys(&[0x1122_3344_5566_7788]).unwrap();
        assert!(one.contains(0x1122_3344_5566_7788));
        assert!(one.len() > 0);

        let keys: Vec<u64> = (0u64..50)
            .map(|i| i.wrapping_mul(0x9e37_79b9_7f4a_7c15))
            .collect();
        let f = BinaryFuse8::try_from_keys(&keys).unwrap();
        for &k in &keys {
            assert!(f.contains(k), "FN on {k:#x}");
        }
        // Re-encode-style field invariants used by fuse8_filter decode.
        assert_eq!(f.segment_length_mask, f.segment_length.saturating_sub(1));
        assert!(f.segment_length >= 4);
        assert!(f.segment_count_length >= f.segment_length);
    }

    #[test]
    fn empty_keys_constructs_via_caller_dummy_only() {
        // size==0 geometry: empty reverse_order / zero stack still builds.
        assert!(BinaryFuse8::try_from_keys(&[]).is_ok());
    }
}
