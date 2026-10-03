//! Datadir-local secret for at-rest script XOR and keyed `tx.head` probes.
//!
//! On **datadir create**, a 32-byte CSPRNG secret is written to `store/store.secret`
//! (mode 0600 when the OS allows). Derived material:
//!
//! - **Script XOR:** `xor_key_byte(i) = secret[i % 32] ^ stream_mix(i)` applied to
//!   on-disk `scriptPubKey`, `scriptSig`, and witness item bytes (Bitcoin Core–style
//!   at-rest obfuscation of script/witness blobs only — not txids or amounts).
//! - **TXID mix:** `mix_txid(txid) = SHA256(secret || txid)` is the **page-local**
//!   probe key for the open `tx.head` segment (15-bit page + in-page double hash).
//!   Without it, anyone can grind ~2¹⁵ SHA256d hashes into one 4 KiB page.
//!   Sealed MPHF/fuse consume the same mixed u64. Mix is not a file-shard selector
//!   (segments are by create_fk range; SH shards are scripthash prefix).
//!
//! Plaintext reconstruct always de-obfuscates on read. Missing secret on open of a
//! schema-12+ store is an error (wipe / recreate datadir).

use crate::error::StoreError;
use bitcoin_hashes::{sha256, Hash};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// On-disk filename under the store directory.
pub const SECRET_FILE: &str = "store.secret";
/// Raw secret length (bytes).
pub const SECRET_LEN: usize = 32;

/// Process-owned datadir secret (clone cheaply via Arc at higher layers).
#[derive(Clone, PartialEq, Eq)]
pub struct StoreSecret {
    bytes: [u8; SECRET_LEN],
}

impl std::fmt::Debug for StoreSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoreSecret(<redacted>)")
    }
}

impl StoreSecret {
    /// Cryptographically random secret (datadir create).
    pub fn generate() -> Self {
        let mut bytes = [0u8; SECRET_LEN];
        getrandom::fill(&mut bytes).expect("CSPRNG for store.secret");
        // Reject all-zero (astronomically unlikely) so tests can detect missing entropy.
        if bytes.iter().all(|&b| b == 0) {
            bytes[0] = 1;
        }
        Self { bytes }
    }

    /// Fixed secret for unit tests (not for production create).
    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        &self.bytes
    }

    /// Persist under `store_dir/store.secret`.
    pub fn write_to_store_dir(&self, store_dir: &Path) -> Result<(), StoreError> {
        let path = secret_path(store_dir);
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path).map_err(|e| StoreError::io(&path, e))?;
        f.write_all(&self.bytes)
            .map_err(|e| StoreError::io(&path, e))?;
        f.sync_all().map_err(|e| StoreError::io(&path, e))?;
        Ok(())
    }

    /// Load existing secret; `Err` if missing or wrong length.
    pub fn load_from_store_dir(store_dir: &Path) -> Result<Self, StoreError> {
        let path = secret_path(store_dir);
        let mut f = std::fs::File::open(&path).map_err(|e| StoreError::io(&path, e))?;
        let mut bytes = [0u8; SECRET_LEN];
        f.read_exact(&mut bytes)
            .map_err(|e| StoreError::io(&path, e))?;

        let mut extra = [0u8; 1];
        match f.read(&mut extra) {
            Ok(0) => {}
            Ok(_) => {
                return Err(StoreError::Corrupt(
                    "store.secret longer than 32 bytes (wipe datadir)",
                ))
            }
            Err(e) => return Err(StoreError::io(&path, e)),
        }
        Ok(Self { bytes })
    }

    /// Load if present; generate+write if create path and file missing.
    pub fn load_or_create(store_dir: &Path, create: bool) -> Result<Self, StoreError> {
        let path = secret_path(store_dir);
        if path.exists() {
            return Self::load_from_store_dir(store_dir);
        }
        if !create {
            return Err(StoreError::Corrupt(
                "store.secret missing (schema 12+ requires wipe or recreate)",
            ));
        }
        let s = Self::generate();
        s.write_to_store_dir(store_dir)?;
        Ok(s)
    }

    /// Stream byte for XOR of script/witness at absolute payload offset `off`.
    #[inline]
    pub fn xor_key_byte(&self, off: u64) -> u8 {
        let i = (off as usize) % SECRET_LEN;
        // Mix position so long scripts do not simply repeat the secret.
        let mix = ((off.wrapping_mul(0x9E37_79B9_7F4A_7C15)) >> 56) as u8;
        self.bytes[i] ^ mix
    }

    /// XOR `buf` in place (encode and decode are the same operation).
    ///
    /// Same stream as [`Self::xor_key_byte`]: 8-byte words, then a tail.
    #[inline]
    pub fn xor_bytes(&self, start_off: u64, buf: &mut [u8]) {
        const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;
        let secret = &self.bytes;
        let mut off = start_off;
        let mut chunks = buf.chunks_exact_mut(8);
        for chunk in chunks.by_ref() {
            let mut k = [0u8; 8];
            for (j, kb) in k.iter_mut().enumerate() {
                let o = off.wrapping_add(j as u64);
                *kb = secret[(o as usize) % SECRET_LEN] ^ ((o.wrapping_mul(GOLDEN) >> 56) as u8);
            }
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            chunk
                .copy_from_slice(&(u64::from_ne_bytes(word) ^ u64::from_ne_bytes(k)).to_ne_bytes());
            off = off.wrapping_add(8);
        }
        for b in chunks.into_remainder() {
            let mix = (off.wrapping_mul(GOLDEN) >> 56) as u8;
            *b ^= secret[(off as usize) % SECRET_LEN] ^ mix;
            off = off.wrapping_add(1);
        }
    }

    /// Keyed mix for open-hash probes: `SHA256(secret || txid)`.
    pub fn mix_txid(&self, txid: &[u8; 32]) -> [u8; 32] {
        let mut eng = sha256::HashEngine::default();
        use bitcoin_hashes::HashEngine;
        eng.input(&self.bytes);
        eng.input(txid);
        let d = sha256::Hash::from_engine(eng);
        *d.as_byte_array()
    }
}

#[inline]
pub fn secret_path(store_dir: &Path) -> PathBuf {
    store_dir.join(SECRET_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> crate::testutil::TempDir {
        crate::testutil::TempDir::labeled("secret").unwrap()
    }

    #[test]
    fn debug_does_not_print_secret_bytes() {
        let s = StoreSecret::from_bytes([0xab; SECRET_LEN]);
        let shown = format!("{s:?}");
        assert!(!shown.contains("abab"), "{shown}");
        assert!(shown.contains("redacted"), "{shown}");
    }

    #[test]
    fn generate_write_load_roundtrip() {
        let dir = temp_dir();
        let s = StoreSecret::generate();
        assert!(s.as_bytes().iter().any(|&b| b != 0));
        s.write_to_store_dir(&dir).unwrap();
        let s2 = StoreSecret::load_from_store_dir(&dir).unwrap();
        assert_eq!(s, s2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn xor_is_involution_and_changes_plaintext() {
        let s = StoreSecret::from_bytes([0xA5; 32]);
        let plain = b"hello-script-pubkey-bytes!!".to_vec();
        let mut buf = plain.clone();
        s.xor_bytes(100, &mut buf);
        assert_ne!(buf, plain, "obfuscated must differ from plaintext");
        s.xor_bytes(100, &mut buf);
        assert_eq!(buf, plain);
    }

    #[test]
    fn xor_bytes_matches_key_byte_stream() {
        let s = StoreSecret::from_bytes([0x3c; 32]);
        let lens = [0usize, 1, 7, 8, 9, 15, 16, 31, 32, 33, 64, 127, 256, 1000];
        let starts = [0u64, 1, 7, 8, 31, 32, 33, 100, 1_000_003];
        for &start in &starts {
            for &len in &lens {
                let mut got = vec![0x5a_u8; len];
                s.xor_bytes(start, &mut got);
                let mut want = vec![0x5a_u8; len];
                for (i, b) in want.iter_mut().enumerate() {
                    *b ^= s.xor_key_byte(start.wrapping_add(i as u64));
                }
                assert_eq!(got, want, "start={start} len={len}");
            }
        }
    }

    #[test]
    fn mix_txid_not_identity_and_stable() {
        let s = StoreSecret::from_bytes([7u8; 32]);
        let txid = [0x11u8; 32];
        let m = s.mix_txid(&txid);
        assert_ne!(m, txid, "mixed key must not equal raw txid");
        assert_eq!(m, s.mix_txid(&txid));
        let m2 = s.mix_txid(&[0x22; 32]);
        assert_ne!(m, m2);
    }

    #[test]
    fn load_or_create_and_missing() {
        let dir = temp_dir();
        assert!(StoreSecret::load_or_create(&dir, false).is_err());
        let s = StoreSecret::load_or_create(&dir, true).unwrap();
        let s2 = StoreSecret::load_or_create(&dir, false).unwrap();
        assert_eq!(s, s2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_rejects_overlong_secret_file() {
        let dir = temp_dir();
        let path = dir.join(SECRET_FILE);
        // 33 bytes → corrupt (longer than 32).
        std::fs::write(&path, vec![0u8; 33]).unwrap();
        assert!(matches!(
            StoreSecret::load_from_store_dir(&dir),
            Err(StoreError::Corrupt(_))
        ));
        // generate forces first byte nonzero path when unlucky zeros — just call once more.
        let mut s = StoreSecret::generate();
        // force first byte path by reconstructing
        let mut b = *s.as_bytes();
        b[0] = 0;
        // from_bytes keeps zero first byte (generate would fix)
        s = StoreSecret::from_bytes(b);
        assert_eq!(s.as_bytes()[0], 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
