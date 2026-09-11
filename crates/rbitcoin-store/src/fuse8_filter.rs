//! Binary fuse8 membership for sealed `tx.head` / SH overflow segments.
//!
//! ~9 bits/key, no false negatives, FP ≈ 2⁻⁸. Built once at seal from mixed
//! probe keys (as u64). Open segments have no filter.
//!
//! On-disk: `BF8R` | u32 version LE | u64 body_len LE | body
//!
//! | Version | Body |
//! |--------:|------|
//! | **1** | Historical: bincode of xorf `BinaryFuse8` (pre in-tree port) — **not** decoded |
//! | **2** | Explicit LE: seed u64 · seg_len u32 · seg_mask u32 · seg_count_len u32 · fp_len u64 · fps |
//!
//! Opening a v1 file **refuses** the store. Wipe `store/tx.head` (and
//! `store/scripthash*` if SH overflow fuses are v1); Class A is kept.

use crate::binary_fuse8::BinaryFuse8;
use crate::error::StoreError;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

const MAGIC: &[u8; 4] = b"BF8R";
/// Historical: bincode of xorf BinaryFuse8. Do not decode with the v2 algorithm.
pub const VERSION_V1: u32 = 1;
/// Explicit LE body (in-tree BinaryFuse8).
pub const VERSION_V2: u32 = 2;

/// One-line operator refuse for leftover fuse8 v1.
pub const INDEX_REFUSE_FUSE8_V1: &str = "index refuses fuse8 v1; wipe store/tx.head and store/scripthash* then restart (Class A kept; tx.head rebuilds, SH rematerializes with --shindex)";

/// Result of opening a sealed fuse file.
#[derive(Clone, Debug)]
pub enum FuseFileOpen {
    /// Current v2 format; safe to use as a membership gate.
    Ready(SealedFuse8),
}

/// On-disk / in-memory sealed fuse for one head segment.
#[derive(Clone, Debug)]
pub struct SealedFuse8 {
    /// `None` ⇒ always probe (migration placeholder; no false negatives).
    filter: Option<BinaryFuse8>,
}

impl SealedFuse8 {
    /// Build from distinct mixed-key u64s (caller must dedupe).
    pub fn build(keys: &[u64]) -> Result<Self, StoreError> {
        if keys.is_empty() {
            // Empty sealed segment: dummy key so construction succeeds.
            return Ok(Self {
                filter: Some(
                    BinaryFuse8::try_from_keys(&[0u64])
                        .map_err(|_| StoreError::Corrupt("binary fuse8 empty build"))?,
                ),
            });
        }
        let filter = BinaryFuse8::try_from_keys(keys)
            .map_err(|_| StoreError::Corrupt("binary fuse8 build failed (dup keys?)"))?;
        Ok(Self {
            filter: Some(filter),
        })
    }

    /// Membership test (no FN for keys passed to [`Self::build`]).
    #[inline]
    pub fn contains(&self, key: u64) -> bool {
        self.filter
            .as_ref()
            .map(|f| f.contains(key))
            .unwrap_or(false)
    }

    /// Fingerprint array length (bytes).
    pub fn fingerprint_bytes(&self) -> usize {
        self.filter.as_ref().map(|f| f.len()).unwrap_or(0)
    }

    /// Write current (v2) layout.
    pub fn write_to(&self, path: &Path) -> Result<(), StoreError> {
        let filter = self
            .filter
            .as_ref()
            .ok_or(StoreError::Corrupt("fuse8 write missing filter"))?;
        let body = encode_body(filter);
        let mut f = File::create(path).map_err(|e| StoreError::io(path, e))?;
        f.write_all(MAGIC).map_err(|e| StoreError::io(path, e))?;
        f.write_all(&VERSION_V2.to_le_bytes())
            .map_err(|e| StoreError::io(path, e))?;
        f.write_all(&(body.len() as u64).to_le_bytes())
            .map_err(|e| StoreError::io(path, e))?;
        f.write_all(&body).map_err(|e| StoreError::io(path, e))?;
        f.sync_all().map_err(|e| StoreError::io(path, e))?;
        Ok(())
    }

    pub fn read_from(path: &Path) -> Result<Self, StoreError> {
        match open_file(path)? {
            FuseFileOpen::Ready(f) => Ok(f),
        }
    }
}

/// Open a BF8R fuse file. v1 and unreadable v2 refuse (no always-probe).
pub fn open_file(path: &Path) -> Result<FuseFileOpen, StoreError> {
    let mut f = File::open(path).map_err(|e| StoreError::io(path, e))?;
    let mut hdr = [0u8; 16];
    f.read_exact(&mut hdr)
        .map_err(|e| StoreError::io(path, e))?;
    if &hdr[0..4] != MAGIC {
        return Err(StoreError::Corrupt("tx.head fuse magic"));
    }
    let ver = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
    let len = u64::from_le_bytes(hdr[8..16].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; len];
    f.read_exact(&mut payload)
        .map_err(|e| StoreError::io(path, e))?;

    match ver {
        VERSION_V1 => Err(StoreError::Corrupt(INDEX_REFUSE_FUSE8_V1)),
        VERSION_V2 => match decode_body(&payload) {
            Ok(filter) => Ok(FuseFileOpen::Ready(SealedFuse8 {
                filter: Some(filter),
            })),
            Err(_) => Err(StoreError::Corrupt("fuse8 v2 body unreadable")),
        },
        _ => Err(StoreError::Corrupt("tx.head fuse version")),
    }
}

fn encode_body(filter: &BinaryFuse8) -> Vec<u8> {
    let fp = filter.fingerprints.as_ref();
    let mut body = Vec::with_capacity(8 + 4 + 4 + 4 + 8 + fp.len());
    body.extend_from_slice(&filter.seed.to_le_bytes());
    body.extend_from_slice(&filter.segment_length.to_le_bytes());
    body.extend_from_slice(&filter.segment_length_mask.to_le_bytes());
    body.extend_from_slice(&filter.segment_count_length.to_le_bytes());
    body.extend_from_slice(&(fp.len() as u64).to_le_bytes());
    body.extend_from_slice(fp);
    body
}

fn decode_body(payload: &[u8]) -> Result<BinaryFuse8, StoreError> {
    if payload.len() < 8 + 4 + 4 + 4 + 8 {
        return Err(StoreError::Corrupt("fuse8 body short"));
    }
    let mut o = 0usize;
    let seed = u64::from_le_bytes(payload[o..o + 8].try_into().unwrap());
    o += 8;
    let segment_length = u32::from_le_bytes(payload[o..o + 4].try_into().unwrap());
    o += 4;
    let segment_length_mask = u32::from_le_bytes(payload[o..o + 4].try_into().unwrap());
    o += 4;
    let segment_count_length = u32::from_le_bytes(payload[o..o + 4].try_into().unwrap());
    o += 4;
    let fp_len = u64::from_le_bytes(payload[o..o + 8].try_into().unwrap()) as usize;
    o += 8;
    // Sanity first: refuse absurd lengths before comparing to payload (avoids
    // saturating arithmetic games and keeps OOM claims out of the heap path).
    if fp_len > 512 * 1024 * 1024 {
        return Err(StoreError::Corrupt("fuse8 fingerprints too large"));
    }
    if payload.len() < o + fp_len {
        return Err(StoreError::Corrupt("fuse8 fingerprints truncated"));
    }
    if segment_length == 0 || segment_length_mask != segment_length.saturating_sub(1) {
        return Err(StoreError::Corrupt("fuse8 segment_length invalid"));
    }
    let fingerprints = payload[o..o + fp_len].to_vec().into_boxed_slice();
    Ok(BinaryFuse8 {
        seed,
        segment_length,
        segment_length_mask,
        segment_count_length,
        fingerprints,
    })
}

/// Fold a 32-byte mixed head key into a u64 fuse key (stable, keyed via mix).
#[inline]
pub fn fuse_key_from_mixed(mixed: &[u8; 32]) -> u64 {
    u64::from_le_bytes(mixed[0..8].try_into().unwrap())
        ^ u64::from_le_bytes(mixed[8..16].try_into().unwrap())
        ^ u64::from_le_bytes(mixed[16..24].try_into().unwrap())
        ^ u64::from_le_bytes(mixed[24..32].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp() -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("rbitcoin-fuse8-{n}"));
        let _ = std::fs::create_dir_all(&p);
        p
    }

    #[test]
    fn no_false_negatives_and_roundtrip() {
        let keys: Vec<u64> = (0..10_000u64)
            .map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(7))
            .collect();
        let f = SealedFuse8::build(&keys).unwrap();
        for &k in &keys {
            assert!(f.contains(k), "FN on {k}");
        }
        let dir = tmp();
        let path = dir.join("seg.fuse8");
        f.write_to(&path).unwrap();
        let f2 = SealedFuse8::read_from(&path).unwrap();
        for &k in &keys {
            assert!(f2.contains(k));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fuse_key_stable() {
        let m = [1u8; 32];
        assert_eq!(fuse_key_from_mixed(&m), fuse_key_from_mixed(&m));
    }

    #[test]
    fn empty_build_and_bad_header_errors() {
        let empty = SealedFuse8::build(&[]).unwrap();
        let _ = empty.contains(0);
        assert!(empty.fingerprint_bytes() > 0);

        let dir = tmp();
        let path = dir.join("bad.fuse8");
        std::fs::write(
            &path,
            b"XXXX\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )
        .unwrap();
        assert!(matches!(open_file(&path), Err(StoreError::Corrupt(_))));
        let mut bad_ver = Vec::from(*MAGIC);
        bad_ver.extend_from_slice(&99u32.to_le_bytes());
        bad_ver.extend_from_slice(&0u64.to_le_bytes());
        std::fs::write(&path, &bad_ver).unwrap();
        assert!(matches!(open_file(&path), Err(StoreError::Corrupt(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn v1_opens_as_index_refuse() {
        let dir = tmp();
        let path = dir.join("legacy.fuse8");
        let mut raw = Vec::from(*MAGIC);
        raw.extend_from_slice(&VERSION_V1.to_le_bytes());
        raw.extend_from_slice(&0u64.to_le_bytes());
        std::fs::write(&path, &raw).unwrap();
        match open_file(&path) {
            Err(StoreError::Corrupt(m)) => {
                assert_eq!(m, INDEX_REFUSE_FUSE8_V1);
                assert!(m.contains("wipe store/tx.head"));
                assert!(m.contains("Class A kept"));
            }
            other => panic!("v1 must refuse, got {other:?}"),
        }
        match SealedFuse8::read_from(&path) {
            Err(StoreError::Corrupt(m)) => assert_eq!(m, INDEX_REFUSE_FUSE8_V1),
            other => panic!("read_from v1 must refuse, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn v2_unreadable_body_is_corrupt() {
        let dir = tmp();
        let path = dir.join("badv2.fuse8");
        let mut raw = Vec::from(*MAGIC);
        raw.extend_from_slice(&VERSION_V2.to_le_bytes());
        raw.extend_from_slice(&4u64.to_le_bytes());
        raw.extend_from_slice(&[0u8; 4]);
        std::fs::write(&path, &raw).unwrap();
        match open_file(&path) {
            Err(StoreError::Corrupt(m)) => assert!(m.contains("unreadable"), "{m}"),
            other => panic!("short v2 body must be Corrupt, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn decode_body_rejects_absurd_fingerprint_len() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u64.to_le_bytes()); // seed
        body.extend_from_slice(&64u32.to_le_bytes()); // seg_len
        body.extend_from_slice(&63u32.to_le_bytes()); // mask
        body.extend_from_slice(&64u32.to_le_bytes()); // count_len
        body.extend_from_slice(&(600 * 1024 * 1024u64).to_le_bytes()); // absurd
                                                                       // no fingerprints
        assert!(decode_body(&body).is_err());
    }

    #[test]
    fn decode_body_rejects_invalid_geometry_and_truncation() {
        // Short header.
        assert!(decode_body(&[0u8; 10]).is_err());
        // Valid geometry header but fingerprints truncated.
        let mut body = Vec::new();
        body.extend_from_slice(&7u64.to_le_bytes());
        body.extend_from_slice(&64u32.to_le_bytes());
        body.extend_from_slice(&63u32.to_le_bytes());
        body.extend_from_slice(&64u32.to_le_bytes());
        body.extend_from_slice(&8u64.to_le_bytes()); // claims 8 fps
        body.extend_from_slice(&[1, 2, 3]); // only 3
        assert!(decode_body(&body).is_err());
        // segment_length == 0
        let mut bad_seg = Vec::new();
        bad_seg.extend_from_slice(&1u64.to_le_bytes());
        bad_seg.extend_from_slice(&0u32.to_le_bytes());
        bad_seg.extend_from_slice(&0u32.to_le_bytes());
        bad_seg.extend_from_slice(&0u32.to_le_bytes());
        bad_seg.extend_from_slice(&0u64.to_le_bytes());
        assert!(decode_body(&bad_seg).is_err());
        // mask != segment_length - 1
        let mut bad_mask = Vec::new();
        bad_mask.extend_from_slice(&1u64.to_le_bytes());
        bad_mask.extend_from_slice(&64u32.to_le_bytes());
        bad_mask.extend_from_slice(&0u32.to_le_bytes()); // wrong mask
        bad_mask.extend_from_slice(&64u32.to_le_bytes());
        bad_mask.extend_from_slice(&0u64.to_le_bytes());
        assert!(decode_body(&bad_mask).is_err());
    }

    #[test]
    fn fuse_key_from_mixed_xors_quarters() {
        let mut m = [0u8; 32];
        m[0] = 1;
        m[8] = 2;
        m[16] = 4;
        m[24] = 8;
        let k = fuse_key_from_mixed(&m);
        assert_eq!(k, 1u64 ^ 2u64 ^ 4u64 ^ 8u64); // LE quarters xor
                                                  // All-zero → zero.
        assert_eq!(fuse_key_from_mixed(&[0u8; 32]), 0);
    }

    #[test]
    fn roundtrip_v2_write_read_and_fingerprint_bytes() {
        let dir = tmp();
        let path = dir.join("rt.fuse8");
        let gate = SealedFuse8::build(&[10u64, 20, 30, 40, 50]).unwrap();
        assert!(gate.fingerprint_bytes() > 0);
        assert!(gate.contains(10));
        assert!(gate.contains(50));
        gate.write_to(&path).unwrap();
        match open_file(&path).unwrap() {
            FuseFileOpen::Ready(g) => {
                assert!(g.contains(10));
                assert!(g.contains(50));
            }
        }
        // Empty keys path builds dummy.
        let empty = SealedFuse8::build(&[]).unwrap();
        assert!(empty.contains(0)); // dummy always built
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_unknown_version_is_corrupt() {
        let dir = tmp();
        let path = dir.join("v99.fuse8");
        let mut raw = Vec::from(*MAGIC);
        raw.extend_from_slice(&99u32.to_le_bytes());
        raw.extend_from_slice(&0u64.to_le_bytes());
        std::fs::write(&path, &raw).unwrap();
        assert!(open_file(&path).is_err());
        // Bad magic.
        std::fs::write(
            &path,
            b"XXXX\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )
        .unwrap();
        assert!(open_file(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
