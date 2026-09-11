//! Sealed `tx.head` shard: value-assigned BDZ MPHF (one candidate).
//!
//! `base.mphf` is BDZ2: `index(key) = newest_rel - 1`. Optional `base.mlt`
//! holds extra older rels for BIP30. A miss is fuse-gated by the caller.

use crate::bdz::BdzMphf;
use crate::error::StoreError;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct TxHeadMphf {
    mphf: BdzMphf,
    mlt: HashMap<u32, Vec<u32>>,
}

pub(crate) struct AssignedKeys {
    pub keys: Vec<u64>,
    pub values: Vec<u32>,
    pub mlt: HashMap<u32, Vec<u32>>,
    pub modulus: u32,
}

/// Unique mixed keys; highest rel per key is the MPHF value, older rels in `mlt`.
pub(crate) fn group_assigned_pairs(pairs: &mut [(u64, u32)]) -> Result<AssignedKeys, StoreError> {
    let mut modulus = 0u32;
    for &(_, rel) in pairs.iter() {
        if rel == 0 {
            return Err(StoreError::Corrupt("tx.head mphf: rel 0"));
        }
        modulus = modulus.max(rel);
    }
    pairs.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let mut keys = Vec::new();
    let mut values = Vec::new();
    let mut mlt = HashMap::new();
    let mut i = 0usize;
    while i < pairs.len() {
        let k = pairs[i].0;
        let mut j = i + 1;
        while j < pairs.len() && pairs[j].0 == k {
            j += 1;
        }
        let newest = pairs[j - 1].1;
        let slot = newest - 1;
        keys.push(k);
        values.push(slot);
        if j - i > 1 {
            let mut extra: Vec<u32> = pairs[i..j - 1].iter().map(|p| p.1).collect();
            extra.reverse();
            mlt.insert(slot, extra);
        }
        i = j;
    }
    keys.shrink_to_fit();
    values.shrink_to_fit();
    Ok(AssignedKeys {
        keys,
        values,
        mlt,
        modulus,
    })
}

pub fn mphf_path(base: &Path) -> PathBuf {
    sidecar(base, ".mphf")
}

pub fn rel_path(base: &Path) -> PathBuf {
    sidecar(base, ".rel")
}

fn mlt_path(base: &Path) -> PathBuf {
    sidecar(base, ".mlt")
}

fn sidecar(base: &Path, ext: &str) -> PathBuf {
    let mut s = base.as_os_str().to_os_string();
    s.push(ext);
    PathBuf::from(s)
}

impl TxHeadMphf {
    pub fn exists(base: &Path) -> bool {
        mphf_path(base).is_file()
    }

    #[cfg(test)]
    pub fn write(base: impl AsRef<Path>, pairs: &[(u64, u32)]) -> Result<Self, StoreError> {
        let mut owned = pairs.to_vec();
        let grouped = group_assigned_pairs(&mut owned)?;
        drop(owned);
        Self::write_grouped(base, grouped)
    }

    pub(crate) fn write_grouped(
        base: impl AsRef<Path>,
        grouped: AssignedKeys,
    ) -> Result<Self, StoreError> {
        let base = base.as_ref();
        if let Some(parent) = base.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mphf = BdzMphf::build_assigned(&grouped.keys, &grouped.values, grouped.modulus)?;
        mphf.write_packed_to(&mphf_path(base))?;
        drop(mphf);
        let rp = rel_path(base);
        if rp.is_file() {
            let _ = std::fs::remove_file(&rp);
        }
        write_mlt(&mlt_path(base), &grouped.mlt)?;
        Self::open(base)
    }

    pub fn open(base: impl AsRef<Path>) -> Result<Self, StoreError> {
        let base = base.as_ref().to_path_buf();
        let mp = mphf_path(&base);
        let mphf = BdzMphf::read_packed_from(&mp)?;
        let rp = rel_path(&base);
        if rp.is_file() {
            eprintln!("store: dropping leftover tx.head .rel (schema 20 MPHF is value-assigned)");
            let _ = std::fs::remove_file(&rp);
        }
        let mlt = read_mlt(&mlt_path(&base))?;
        Ok(Self { mphf, mlt })
    }

    #[cfg(test)]
    pub fn slots_for(&self, mixed_u64: &[u64]) -> Result<Vec<u32>, StoreError> {
        self.slots_for_ctx(mixed_u64, &mut crate::IoCtx::none())
    }

    pub fn slots_for_ctx(
        &self,
        mixed_u64: &[u64],
        ctx: &mut crate::IoCtx<'_>,
    ) -> Result<Vec<u32>, StoreError> {
        self.mphf.index_batch(mixed_u64, ctx)
    }

    #[cfg(test)]
    pub fn take_g_page_preads(&self) -> u64 {
        self.mphf.take_g_page_preads()
    }

    pub fn g_bytes_resident(&self) -> u64 {
        self.mphf.g_bytes_resident() as u64
    }

    pub fn read_rels_batch(
        &self,
        slots: &[u32],
        _ctx: &mut crate::IoCtx<'_>,
    ) -> Result<Vec<Vec<u32>>, StoreError> {
        let mut out = vec![Vec::new(); slots.len()];
        for (i, &slot) in slots.iter().enumerate() {
            out[i].push(slot + 1);
            if let Some(extra) = self.mlt.get(&slot) {
                out[i].extend_from_slice(extra);
            }
        }
        Ok(out)
    }
}

fn write_mlt(path: &Path, mlt: &HashMap<u32, Vec<u32>>) -> Result<(), StoreError> {
    if mlt.is_empty() {
        let _ = std::fs::remove_file(path);
        return Ok(());
    }
    let mut buf = Vec::new();
    buf.extend_from_slice(&(mlt.len() as u32).to_le_bytes());
    for (&slot, rels) in mlt {
        buf.extend_from_slice(&slot.to_le_bytes());
        buf.extend_from_slice(&(rels.len() as u16).to_le_bytes());
        for r in rels {
            buf.extend_from_slice(&r.to_le_bytes());
        }
    }
    std::fs::write(path, &buf).map_err(|e| StoreError::io(path, e))?;
    Ok(())
}

fn read_mlt(path: &Path) -> Result<HashMap<u32, Vec<u32>>, StoreError> {
    if !path.is_file() {
        return Ok(HashMap::new());
    }
    let buf = std::fs::read(path).map_err(|e| StoreError::io(path, e))?;
    if buf.len() < 4 {
        return Err(StoreError::Corrupt("tx.head mlt short"));
    }
    let n = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
    let mut i = 4usize;
    let mut out = HashMap::new();
    for _ in 0..n {
        if i + 6 > buf.len() {
            return Err(StoreError::Corrupt("tx.head mlt truncated"));
        }
        let slot = u32::from_le_bytes(buf[i..i + 4].try_into().unwrap());
        i += 4;
        let nrel = u16::from_le_bytes(buf[i..i + 2].try_into().unwrap()) as usize;
        i += 2;
        if i + nrel * 4 > buf.len() {
            return Err(StoreError::Corrupt("tx.head mlt rels"));
        }
        let mut rels = Vec::with_capacity(nrel);
        for _ in 0..nrel {
            rels.push(u32::from_le_bytes(buf[i..i + 4].try_into().unwrap()));
            i += 4;
        }
        out.insert(slot, rels);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bdz::BdzMphf;
    use crate::uring_session::{IoCtx, SessionKind, UringSession};

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rbitcoin-tx-mphf-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn shared_g_page_is_one_pread() {
        let dir = tmp("share");
        std::fs::create_dir_all(&dir).unwrap();
        let keys: Vec<u64> = (0..4_000u64)
            .map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(3))
            .collect();
        let ram = BdzMphf::build(&keys).unwrap();
        let p = dir.join("t.mphf");
        ram.write_to(&p).unwrap();
        let fd = BdzMphf::read_from(&p).unwrap();
        let page_of = |k: u64| {
            fd.vertices(k)
                .into_iter()
                .map(|v| v / 1024)
                .collect::<Vec<_>>()
        };
        let k0 = keys[0];
        let p0 = page_of(k0);
        let k1 = keys
            .iter()
            .copied()
            .find(|&k| k != k0 && page_of(k).iter().any(|p| p0.contains(p)))
            .expect("two keys sharing a g page");
        let _ = fd.take_g_page_preads();
        let a = fd.index(k0).unwrap();
        let b = fd.index(k1).unwrap();
        let serial_pages = fd.take_g_page_preads();
        let batch = fd.index_batch(&[k0, k1], &mut IoCtx::none()).unwrap();
        let batch_pages = fd.take_g_page_preads();
        assert_eq!(batch, vec![a, b]);
        let mut uniq = page_of(k0);
        uniq.extend(page_of(k1));
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(batch_pages, uniq.len() as u64);
        assert!(batch_pages <= serial_pages);
        assert!(batch_pages >= 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn index_batch_held_session_submits_g_pages() {
        let dir = tmp("held");
        std::fs::create_dir_all(&dir).unwrap();
        let keys: Vec<u64> = (0..200u64).map(|i| i * 17 + 3).collect();
        let ram = BdzMphf::build(&keys).unwrap();
        let p = dir.join("t.mphf");
        ram.write_to(&p).unwrap();
        let fd = BdzMphf::read_from(&p).unwrap();
        let serial = fd.index_batch(&keys[..8], &mut IoCtx::none()).unwrap();
        let mut session = UringSession::try_open_kind(SessionKind::Pool, 32).expect("pool");
        let _ = session.take_sqe_n();
        let mut ctx = IoCtx::held(&mut session);
        let batch = fd.index_batch(&keys[..8], &mut ctx).unwrap();
        session.drain_all().unwrap();
        assert_eq!(batch, serial);
        assert!(
            session.take_sqe_n() > 0,
            "index_batch(held) must submit g pages on the held session"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Held-session leftover `KIND_BULK_PREAD` must not be harvested as a BDZ
    /// g-page CQE (`bdz g page bad slot`). Drain the foreign SQE first.
    #[test]
    fn index_batch_held_session_drains_foreign_kind_leftover() {
        use std::io::Write;
        let dir = tmp("held-leftover");
        std::fs::create_dir_all(&dir).unwrap();
        let keys: Vec<u64> = (0..200u64).map(|i| i * 17 + 3).collect();
        let ram = BdzMphf::build(&keys).unwrap();
        let p = dir.join("t.mphf");
        ram.write_to(&p).unwrap();
        let fd_mphf = BdzMphf::read_from(&p).unwrap();
        let serial = fd_mphf.index_batch(&keys[..8], &mut IoCtx::none()).unwrap();

        let leftover_path = dir.join("leftover.bin");
        let mut leftover_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&leftover_path)
            .unwrap();
        leftover_file.write_all(&[0xAAu8; 8]).unwrap();
        leftover_file.sync_all().unwrap();
        let leftover_fd = crate::io_handle::IoHandle::from_file(&leftover_file);

        let mut session = UringSession::try_open_kind(SessionKind::Pool, 32).expect("pool");
        session.begin_batch().unwrap();
        let mut leftover_buf = [0u8; 8];
        let ud = crate::uring_session::pack_ud(
            crate::uring_session::KIND_BULK_PREAD,
            session.epoch(),
            0,
        );
        session
            .push_pread(leftover_fd, 0, &mut leftover_buf, ud)
            .unwrap();
        session.submit().unwrap();
        assert!(
            session.in_flight() > 0,
            "foreign SQE must still be pending when BDZ starts"
        );

        let batch = {
            let mut ctx = IoCtx::held(&mut session);
            fd_mphf
                .index_batch(&keys[..8], &mut ctx)
                .unwrap_or_else(|e| {
                    panic!("held index_batch with leftover KIND_BULK_PREAD must drain, not {e}")
                })
        };
        session.drain_all().unwrap();
        assert_eq!(batch, serial);
        assert_eq!(session.in_flight(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tx_head_mphf_open_is_header_only() {
        let dir = tmp("open");
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("000000");
        let pairs: Vec<(u64, u32)> = (1..64u32)
            .map(|i| (u64::from(i).wrapping_mul(0x9e37_79b9_7f4a_7c15), i))
            .collect();
        let h = TxHeadMphf::write(&base, &pairs).unwrap();
        assert_eq!(h.mphf.g_bytes_resident(), 0);
        assert!(!rel_path(&base).is_file());
        assert_eq!(&std::fs::read(mphf_path(&base)).unwrap()[0..4], b"BDZ2");
        let slots = h.slots_for(&[pairs[0].0]).unwrap();
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0], pairs[0].1 - 1);
        let rels = h
            .read_rels_batch(&slots, &mut crate::IoCtx::none())
            .unwrap();
        assert_eq!(rels[0][0], pairs[0].1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn group_assigned_pairs_unique_and_bip30_newest() {
        assert!(group_assigned_pairs(&mut []).unwrap().keys.is_empty());
        assert!(matches!(
            group_assigned_pairs(&mut [(1, 0)]),
            Err(StoreError::Corrupt(_))
        ));
        let mut pairs = vec![(10u64, 2u32), (20, 1), (10, 5), (10, 3), (30, 4)];
        let g = group_assigned_pairs(&mut pairs).unwrap();
        assert_eq!(g.modulus, 5);
        let mut got: Vec<(u64, u32)> = g
            .keys
            .iter()
            .copied()
            .zip(g.values.iter().copied())
            .collect();
        got.sort_unstable();
        assert_eq!(got, vec![(10, 4), (20, 0), (30, 3)]);
        assert_eq!(g.mlt.get(&4), Some(&vec![3, 2]));
        assert_eq!(g.mlt.len(), 1);
    }

    #[test]
    fn tx_head_mphf_unlinks_leftover_rel_and_bip30_mlt() {
        let dir = tmp("leftover-rel");
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("000000");
        let key = 0xB1B0_u64;
        let pairs = vec![(key, 1u32), (0x2222, 2), (key, 3)];
        std::fs::write(rel_path(&base), [1u8, 2, 3, 4]).unwrap();
        let h = TxHeadMphf::write(&base, &pairs).unwrap();
        assert!(!rel_path(&base).is_file());
        let slots = h.slots_for(&[key]).unwrap();
        assert_eq!(slots, vec![2]);
        let rels = h
            .read_rels_batch(&slots, &mut crate::IoCtx::none())
            .unwrap();
        assert_eq!(rels[0], vec![3, 1]);
        std::fs::write(rel_path(&base), [9u8; 4]).unwrap();
        let h2 = TxHeadMphf::open(&base).unwrap();
        assert!(!rel_path(&base).is_file());
        assert_eq!(
            h2.read_rels_batch(&slots, &mut crate::IoCtx::none())
                .unwrap()[0],
            vec![3, 1]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
