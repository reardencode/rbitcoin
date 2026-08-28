//! In-tree BDZ 3-graph MPHF (`u64` keys → `[0, n)`).
//!
//! A key **not** in the set still maps into `[0, n)`. Callers verify identity.

use crate::error::StoreError;
use crate::io_handle::IoHandle;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAGIC2: &[u8; 4] = b"BDZ2";
const MAGIC3: &[u8; 4] = b"BDZ3";
const VERSION: u32 = 1;
const GAMMA_NUM: u64 = 123;
const GAMMA_DEN: u64 = 100;
const MAX_SEED: u32 = 256;
const HEADER_LEN2: u64 = 32;
const HEADER_LEN3: u64 = 32;
const G_PAGE_BYTES: usize = 4096;
const G_BITS_WORDS: u32 = 32;
const COMPACT_G_BITS: u32 = 2;
const RANK_SUPER_BITS: u32 = 512;

#[derive(Debug)]
enum GStore {
    Ram(Box<[u32]>),
    Fd {
        file: File,
        path: PathBuf,
        off: u64,
        n_bytes: u64,
        g_bits: u32,
        page_preads: AtomicU64,
    },
}

#[derive(Debug)]
struct CompactRank {
    m: u32,
    occ: Box<[u64]>,
    supers: Box<[u32]>,
}

#[derive(Debug)]
pub struct BdzMphf {
    n: u32,
    m: u32,
    seed: u64,
    modulus: u32,
    g: GStore,
    compact: Option<CompactRank>,
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
fn hash3(key: u64, seed: u64, m: u32) -> [u32; 3] {
    let h = mix64(key.wrapping_add(seed));
    let m = m as u64;
    let a = ((h as u128 * m as u128) >> 64) as u32;
    let b = ((h.rotate_left(21) as u128 * m as u128) >> 64) as u32;
    let c = ((h.rotate_left(42) as u128 * m as u128) >> 64) as u32;
    let mut out = [a, b, c];
    if out[1] == out[0] {
        out[1] = (out[1] + 1) % (m as u32);
    }
    if out[2] == out[0] || out[2] == out[1] {
        out[2] = (out[2] + 1) % (m as u32);
        if out[2] == out[0] || out[2] == out[1] {
            out[2] = (out[2] + 1) % (m as u32);
        }
    }
    out
}

#[inline]
fn hash3_partite(key: u64, seed: u64, m: u32) -> [u32; 3] {
    let part = m / 3;
    let h = mix64(key.wrapping_add(seed));
    let p = part as u64;
    let a = ((h as u128 * p as u128) >> 64) as u32;
    let b = ((h.rotate_left(21) as u128 * p as u128) >> 64) as u32;
    let c = ((h.rotate_left(42) as u128 * p as u128) >> 64) as u32;
    [a, part + b, 2 * part + c]
}

#[inline]
fn hash_verts(key: u64, seed: u64, m: u32, partite: bool) -> [u32; 3] {
    if partite {
        hash3_partite(key, seed, m)
    } else {
        hash3(key, seed, m)
    }
}

impl BdzMphf {
    pub fn n(&self) -> u32 {
        self.n
    }

    #[cfg(test)]
    pub fn modulus(&self) -> u32 {
        self.modulus
    }

    #[cfg(test)]
    pub fn g_bytes(&self) -> usize {
        match &self.g {
            GStore::Ram(g) => g.len() * 4,
            GStore::Fd { n_bytes, .. } => *n_bytes as usize,
        }
    }

    pub fn g_bytes_resident(&self) -> usize {
        match &self.g {
            GStore::Ram(g) => g.len() * 4,
            GStore::Fd { .. } => 0,
        }
    }

    #[cfg(test)]
    pub fn vertices(&self, key: u64) -> [u32; 3] {
        if self.n <= 1 {
            return [0, 0, 0];
        }
        hash_verts(key, self.seed, self.m, self.compact.is_some())
    }

    pub fn index(&self, key: u64) -> Result<u32, StoreError> {
        Ok(self.index_batch(&[key], &mut crate::IoCtx::none())?[0])
    }

    #[cfg(test)]
    pub fn take_g_page_preads(&self) -> u64 {
        match &self.g {
            GStore::Fd { page_preads, .. } => page_preads.swap(0, Ordering::Relaxed),
            GStore::Ram(_) => 0,
        }
    }

    pub fn index_batch(
        &self,
        keys: &[u64],
        ctx: &mut crate::IoCtx<'_>,
    ) -> Result<Vec<u32>, StoreError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        if self.n == 0 {
            return Ok(vec![0; keys.len()]);
        }
        if self.n == 1 {
            return Ok(vec![self.one_key_index()?; keys.len()]);
        }
        match &self.g {
            GStore::Ram(g) => Ok(keys.iter().map(|&k| self.index_from_g(g, k)).collect()),
            GStore::Fd { .. } => self.index_batch_fd(keys, ctx),
        }
    }

    fn index_from_g(&self, g: &[u32], key: u64) -> u32 {
        let partite = self.compact.is_some();
        let [a, b, c] = hash_verts(key, self.seed, self.m, partite);
        let ga = g[a as usize];
        let gb = g[b as usize];
        let gc = g[c as usize];
        self.finish_index(ga, gb, gc, [a, b, c])
    }

    fn finish_index(&self, ga: u32, gb: u32, gc: u32, verts: [u32; 3]) -> u32 {
        if let Some(rank) = self.compact.as_ref() {
            let i = (ga.wrapping_add(gb).wrapping_add(gc) % 3) as usize;
            let v = verts[i];
            rank.rank1(v).min(self.n.saturating_sub(1))
        } else {
            ga.wrapping_add(gb).wrapping_add(gc) % self.modulus
        }
    }

    fn index_batch_fd(
        &self,
        keys: &[u64],
        ctx: &mut crate::IoCtx<'_>,
    ) -> Result<Vec<u32>, StoreError> {
        let GStore::Fd {
            file,
            path,
            off,
            n_bytes,
            g_bits,
            page_preads,
            ..
        } = &self.g
        else {
            return Err(StoreError::Corrupt("bdz mphf: fd batch"));
        };
        let g_bits = *g_bits;
        let partite = self.compact.is_some();
        let verts: Vec<[u32; 3]> = keys
            .iter()
            .map(|&k| hash_verts(k, self.seed, self.m, partite))
            .collect();
        let mut page_ids: Vec<u32> = verts
            .iter()
            .flat_map(|v| {
                v.iter()
                    .copied()
                    .flat_map(|vert| vertex_pages(vert, g_bits))
            })
            .collect();
        page_ids.sort_unstable();
        page_ids.dedup();
        let mut scatter = GPageScatter::from_verts(g_bits, &verts, &page_ids);
        stream_or_load_pages(
            file,
            path,
            *off,
            *n_bytes,
            &page_ids,
            page_preads,
            ctx,
            &mut |page, buf| scatter.fill(page, buf),
        )?;
        Ok(scatter
            .words
            .iter()
            .zip(verts.iter())
            .map(|([ga, gb, gc], verts)| self.finish_index(*ga, *gb, *gc, *verts))
            .collect())
    }

    fn one_key_index(&self) -> Result<u32, StoreError> {
        if self.compact.is_some() {
            return Ok(0);
        }
        match &self.g {
            GStore::Ram(g) => Ok(g.first().copied().unwrap_or(0)),
            GStore::Fd {
                file,
                path,
                off,
                g_bits,
                ..
            } => {
                if *g_bits == G_BITS_WORDS {
                    let mut buf = [0u8; 4];
                    pread_exact(file, path, *off, &mut buf)?;
                    return Ok(u32::from_le_bytes(buf));
                }
                let nbytes = ((*g_bits as usize) + 7) / 8;
                let mut buf = vec![0u8; nbytes.max(1)];
                pread_exact(file, path, *off, &mut buf)?;
                Ok(unpack_g_at(&buf, 0, *g_bits))
            }
        }
    }

    #[cfg(test)]
    pub fn build(keys: &[u64]) -> Result<Self, StoreError> {
        let n = keys.len() as u32;
        let ranks: Vec<u32> = (0..n).collect();
        Self::build_from_ranks(keys, &ranks, n)
    }

    pub fn build_assigned(keys: &[u64], values: &[u32], modulus: u32) -> Result<Self, StoreError> {
        if keys.len() != values.len() {
            return Err(StoreError::Corrupt("bdz mphf: assigned len"));
        }
        if keys.is_empty() {
            return Self::build_from_ranks(keys, values, modulus);
        }
        if modulus == 0 {
            return Err(StoreError::Corrupt("bdz mphf: assigned modulus"));
        }
        let mut seen = vec![false; modulus as usize];
        for &v in values {
            if v >= modulus {
                return Err(StoreError::Corrupt("bdz mphf: assigned value"));
            }
            if seen[v as usize] {
                return Err(StoreError::Corrupt("bdz mphf: assigned duplicate"));
            }
            seen[v as usize] = true;
        }
        Self::build_from_ranks(keys, values, modulus)
    }

    fn build_from_ranks(keys: &[u64], ranks: &[u32], modulus: u32) -> Result<Self, StoreError> {
        let n = keys.len() as u32;
        if n == 0 {
            return Ok(Self {
                n: 0,
                m: 0,
                seed: 0,
                modulus,
                g: GStore::Ram(Box::new([])),
                compact: None,
            });
        }
        if n == 1 {
            return Ok(Self {
                n: 1,
                m: 1,
                seed: 1,
                modulus,
                g: GStore::Ram(vec![ranks[0]].into_boxed_slice()),
                compact: None,
            });
        }
        let m = ((u64::from(n) * GAMMA_NUM + GAMMA_DEN - 1) / GAMMA_DEN)
            .max(u64::from(n) + 3)
            .max(3) as u32;
        let mut rng = 0x9e37_79b9_7f4a_7c15u64;
        let mut scratch = PeelScratch::default();
        for _try in 0..MAX_SEED {
            let seed = splitmix64(&mut rng);
            scratch.prepare(m as usize, keys.len());
            if peel_order(keys, seed, m, &mut scratch, false) {
                let order = std::mem::take(&mut scratch.order);
                drop(scratch);
                let g = assign_g(keys, ranks, seed, m, modulus, &order);
                return Ok(Self {
                    n,
                    m,
                    seed,
                    modulus,
                    g: GStore::Ram(g.into_boxed_slice()),
                    compact: None,
                });
            }
        }
        Err(StoreError::Corrupt("bdz mphf: graph did not peel"))
    }

    #[cfg(test)]
    pub fn write_to(&self, path: &Path) -> Result<(), StoreError> {
        const MAGIC: &[u8; 4] = b"BDZ1";
        const HEADER_LEN: u64 = 24;
        let GStore::Ram(g) = &self.g else {
            return Err(StoreError::Corrupt("bdz mphf: write requires RAM g"));
        };
        let mut buf = Vec::with_capacity(HEADER_LEN as usize + g.len() * 4);
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&self.n.to_le_bytes());
        buf.extend_from_slice(&self.m.to_le_bytes());
        buf.extend_from_slice(&self.seed.to_le_bytes());
        for &x in g.iter() {
            buf.extend_from_slice(&x.to_le_bytes());
        }
        std::fs::write(path, &buf).map_err(|e| StoreError::io(path, e))?;
        Ok(())
    }

    pub fn write_packed_to(&self, path: &Path) -> Result<(), StoreError> {
        let GStore::Ram(g) = &self.g else {
            return Err(StoreError::Corrupt("bdz mphf: write requires RAM g"));
        };
        let g_bits = g_bits_for_modulus(self.modulus);
        let mut f = std::fs::File::create(path).map_err(|e| StoreError::io(path, e))?;
        let mut hdr = [0u8; HEADER_LEN2 as usize];
        hdr[0..4].copy_from_slice(MAGIC2);
        hdr[4..8].copy_from_slice(&VERSION.to_le_bytes());
        hdr[8..12].copy_from_slice(&self.n.to_le_bytes());
        hdr[12..16].copy_from_slice(&self.m.to_le_bytes());
        hdr[16..24].copy_from_slice(&self.seed.to_le_bytes());
        hdr[24..28].copy_from_slice(&self.modulus.to_le_bytes());
        hdr[28..32].copy_from_slice(&g_bits.to_le_bytes());
        f.write_all(&hdr).map_err(|e| StoreError::io(path, e))?;
        pack_g_write(g, g_bits, &mut f).map_err(|e| StoreError::io(path, e))?;
        f.sync_all().map_err(|e| StoreError::io(path, e))?;
        Ok(())
    }

    #[cfg(test)]
    pub fn read_from(path: &Path) -> Result<Self, StoreError> {
        const MAGIC: &[u8; 4] = b"BDZ1";
        const HEADER_LEN: u64 = 24;
        let file = File::open(path).map_err(|e| StoreError::io(path, e))?;
        let mut hdr = [0u8; HEADER_LEN as usize];
        pread_exact(&file, path, 0, &mut hdr)?;
        if &hdr[0..4] != MAGIC {
            return Err(StoreError::Corrupt("bdz mphf: bad magic"));
        }
        let ver = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
        if ver != VERSION {
            return Err(StoreError::Corrupt("bdz mphf: bad version"));
        }
        let n = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        let m = u32::from_le_bytes(hdr[12..16].try_into().unwrap());
        let seed = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
        if n == 0 {
            return Ok(Self {
                n: 0,
                m: 0,
                seed: 0,
                modulus: 0,
                g: GStore::Ram(Box::new([])),
                compact: None,
            });
        }
        let n_words = if n == 1 { 1 } else { m };
        let g_bytes = n_words as u64 * 4;
        let meta = file.metadata().map_err(|e| StoreError::io(path, e))?;
        if meta.len() < HEADER_LEN + g_bytes {
            return Err(StoreError::Corrupt("bdz mphf: g length"));
        }
        Ok(Self {
            n,
            m: n_words,
            seed,
            modulus: n,
            g: GStore::Fd {
                file,
                path: path.to_path_buf(),
                off: HEADER_LEN,
                n_bytes: g_bytes,
                g_bits: G_BITS_WORDS,
                page_preads: AtomicU64::new(0),
            },
            compact: None,
        })
    }

    pub fn read_packed_from(path: &Path) -> Result<Self, StoreError> {
        let file = File::open(path).map_err(|e| StoreError::io(path, e))?;
        let mut hdr = [0u8; HEADER_LEN2 as usize];
        pread_exact(&file, path, 0, &mut hdr)?;
        if &hdr[0..4] != MAGIC2 {
            return Err(StoreError::Corrupt("bdz mphf: bad magic"));
        }
        let ver = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
        if ver != VERSION {
            return Err(StoreError::Corrupt("bdz mphf: bad version"));
        }
        let n = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        let m = u32::from_le_bytes(hdr[12..16].try_into().unwrap());
        let seed = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
        let modulus = u32::from_le_bytes(hdr[24..28].try_into().unwrap());
        let g_bits = u32::from_le_bytes(hdr[28..32].try_into().unwrap());
        if g_bits == 0 || g_bits > 32 {
            return Err(StoreError::Corrupt("bdz mphf: g_bits"));
        }
        if n == 0 {
            return Ok(Self {
                n: 0,
                m: 0,
                seed: 0,
                modulus,
                g: GStore::Ram(Box::new([])),
                compact: None,
            });
        }
        let n_verts = if n == 1 { 1 } else { m };
        let n_bytes = packed_g_bytes(n_verts, g_bits);
        let meta = file.metadata().map_err(|e| StoreError::io(path, e))?;
        if meta.len() < HEADER_LEN2 + n_bytes {
            return Err(StoreError::Corrupt("bdz mphf: g length"));
        }
        Ok(Self {
            n,
            m: n_verts,
            seed,
            modulus,
            g: GStore::Fd {
                file,
                path: path.to_path_buf(),
                off: HEADER_LEN2,
                n_bytes,
                g_bits,
                page_preads: AtomicU64::new(0),
            },
            compact: None,
        })
    }

    pub fn build_compact(keys: &[u64]) -> Result<Self, StoreError> {
        let n = keys.len() as u32;
        if n == 0 {
            return Ok(Self {
                n: 0,
                m: 0,
                seed: 0,
                modulus: 0,
                g: GStore::Ram(Box::new([])),
                compact: Some(CompactRank::empty()),
            });
        }
        if n == 1 {
            let mut occ = vec![0u64; 1];
            occ_set(&mut occ, 0);
            return Ok(Self {
                n: 1,
                m: 1,
                seed: 1,
                modulus: 1,
                g: GStore::Ram(vec![0].into_boxed_slice()),
                compact: Some(CompactRank::from_occ(occ.into_boxed_slice(), 1)),
            });
        }
        let m = compact_vertex_count(n);
        let mut rng = 0x9e37_79b9_7f4a_7c15u64;
        let mut scratch = PeelScratch::default();
        for _try in 0..MAX_SEED {
            let seed = splitmix64(&mut rng);
            scratch.prepare(m as usize, keys.len());
            if peel_order(keys, seed, m, &mut scratch, true) {
                let order = std::mem::take(&mut scratch.order);
                drop(scratch);
                let (g, occ) = assign_compact(keys, seed, m, &order);
                return Ok(Self {
                    n,
                    m,
                    seed,
                    modulus: n,
                    g: GStore::Ram(g.into_boxed_slice()),
                    compact: Some(CompactRank::from_occ(occ, m)),
                });
            }
        }
        Err(StoreError::Corrupt("bdz mphf: graph did not peel"))
    }

    pub fn write_compact_to(&self, path: &Path) -> Result<(), StoreError> {
        let GStore::Ram(g) = &self.g else {
            return Err(StoreError::Corrupt("bdz mphf: write requires RAM g"));
        };
        let Some(rank) = self.compact.as_ref() else {
            return Err(StoreError::Corrupt("bdz mphf: compact write"));
        };
        let mut f = std::fs::File::create(path).map_err(|e| StoreError::io(path, e))?;
        let mut hdr = [0u8; HEADER_LEN3 as usize];
        hdr[0..4].copy_from_slice(MAGIC3);
        hdr[4..8].copy_from_slice(&VERSION.to_le_bytes());
        hdr[8..12].copy_from_slice(&self.n.to_le_bytes());
        hdr[12..16].copy_from_slice(&self.m.to_le_bytes());
        hdr[16..24].copy_from_slice(&self.seed.to_le_bytes());
        hdr[24..28].copy_from_slice(&0u32.to_le_bytes());
        hdr[28..32].copy_from_slice(&COMPACT_G_BITS.to_le_bytes());
        f.write_all(&hdr).map_err(|e| StoreError::io(path, e))?;
        if self.n > 0 {
            pack_g_write(g, COMPACT_G_BITS, &mut f).map_err(|e| StoreError::io(path, e))?;
            write_occ(&rank.occ, rank.m, &mut f).map_err(|e| StoreError::io(path, e))?;
        }
        f.sync_all().map_err(|e| StoreError::io(path, e))?;
        Ok(())
    }

    pub fn read_compact_from(path: &Path) -> Result<Self, StoreError> {
        let file = File::open(path).map_err(|e| StoreError::io(path, e))?;
        let mut hdr = [0u8; HEADER_LEN3 as usize];
        pread_exact(&file, path, 0, &mut hdr)?;
        if &hdr[0..4] != MAGIC3 {
            return Err(StoreError::Corrupt("bdz mphf: bad magic"));
        }
        let ver = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
        if ver != VERSION {
            return Err(StoreError::Corrupt("bdz mphf: bad version"));
        }
        let n = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        let m = u32::from_le_bytes(hdr[12..16].try_into().unwrap());
        let seed = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
        let g_bits = u32::from_le_bytes(hdr[28..32].try_into().unwrap());
        if g_bits != COMPACT_G_BITS {
            return Err(StoreError::Corrupt("bdz mphf: g_bits"));
        }
        if n == 0 {
            return Ok(Self {
                n: 0,
                m: 0,
                seed: 0,
                modulus: 0,
                g: GStore::Ram(Box::new([])),
                compact: Some(CompactRank::empty()),
            });
        }
        let n_verts = if n == 1 { 1 } else { m };
        let g_bytes = packed_g_bytes(n_verts, COMPACT_G_BITS);
        let occ_n = occ_packed_bytes(n_verts) as usize;
        let meta = file.metadata().map_err(|e| StoreError::io(path, e))?;
        if meta.len() < HEADER_LEN3 + g_bytes + occ_n as u64 {
            return Err(StoreError::Corrupt("bdz mphf: g length"));
        }
        let mut occ_buf = vec![0u8; occ_n];
        pread_exact(&file, path, HEADER_LEN3 + g_bytes, &mut occ_buf)?;
        let occ = read_occ(&occ_buf, n_verts);
        Ok(Self {
            n,
            m: n_verts,
            seed,
            modulus: n,
            g: GStore::Fd {
                file,
                path: path.to_path_buf(),
                off: HEADER_LEN3,
                n_bytes: g_bytes,
                g_bits: COMPACT_G_BITS,
                page_preads: AtomicU64::new(0),
            },
            compact: Some(CompactRank::from_occ(occ, n_verts)),
        })
    }

    pub fn trailer_off(&self) -> u64 {
        if self.n == 0 {
            return HEADER_LEN3;
        }
        HEADER_LEN3 + packed_g_bytes(self.m, COMPACT_G_BITS) + occ_packed_bytes(self.m)
    }
}

fn pread_exact(file: &File, path: &Path, offset: u64, buf: &mut [u8]) -> Result<(), StoreError> {
    let h = IoHandle::from_file(file);
    let mut done = 0usize;
    while done < buf.len() {
        let n = h.pread(offset + done as u64, &mut buf[done..]);
        if n < 0 {
            return Err(StoreError::io(path, std::io::Error::from_raw_os_error(-n)));
        }
        if n == 0 {
            return Err(StoreError::Corrupt("bdz mphf: short pread"));
        }
        done += n as usize;
    }
    Ok(())
}

fn g_page_need(n_bytes: u64, page: u32) -> usize {
    let page_base = u64::from(page) * G_PAGE_BYTES as u64;
    if page_base >= n_bytes {
        return 0;
    }
    ((n_bytes - page_base) as usize).min(G_PAGE_BYTES)
}

fn load_g_page(
    file: &File,
    path: &Path,
    g_off: u64,
    n_bytes: u64,
    page: u32,
    buf: &mut [u8; G_PAGE_BYTES],
) -> Result<usize, StoreError> {
    let need = g_page_need(n_bytes, page);
    if need == 0 {
        return Ok(0);
    }
    pread_exact(
        file,
        path,
        g_off + u64::from(page) * G_PAGE_BYTES as u64,
        &mut buf[..need],
    )?;
    Ok(need)
}

fn stream_or_load_pages(
    file: &File,
    path: &Path,
    off: u64,
    n_bytes: u64,
    page_ids: &[u32],
    page_preads: &AtomicU64,
    ctx: &mut crate::IoCtx<'_>,
    fill: &mut impl FnMut(u32, &[u8]),
) -> Result<(), StoreError> {
    match ctx.session() {
        Some(session) => stream_g_pages(
            session,
            file,
            path,
            off,
            n_bytes,
            page_ids,
            page_preads,
            fill,
        ),
        None => {
            for &page in page_ids {
                let mut buf = [0u8; G_PAGE_BYTES];
                let n = load_g_page(file, path, off, n_bytes, page, &mut buf)?;
                page_preads.fetch_add(1, Ordering::Relaxed);
                fill(page, &buf[..n]);
            }
            Ok(())
        }
    }
}

fn stream_g_pages(
    session: &mut crate::uring_session::UringSession,
    file: &File,
    path: &Path,
    g_off: u64,
    n_bytes: u64,
    page_ids: &[u32],
    page_preads: &AtomicU64,
    fill: &mut impl FnMut(u32, &[u8]),
) -> Result<(), StoreError> {
    let n_pages = page_ids.len();
    if n_pages == 0 {
        return Ok(());
    }
    let fd = IoHandle::from_file(file);
    let pool_n = (crate::uring_session::DEFAULT_ENTRIES as usize)
        .min(n_pages)
        .max(1);
    let mut bufs: Vec<[u8; G_PAGE_BYTES]> = vec![[0u8; G_PAGE_BYTES]; pool_n];
    let mut slot_page: Vec<Option<usize>> = vec![None; pool_n];
    let mut free_slots: Vec<usize> = (0..pool_n).collect();
    let mut next_page = 0usize;
    let mut in_flight = 0usize;
    session.begin_batch()?;
    let epoch = session.epoch();
    let run = (|| -> Result<(), StoreError> {
        loop {
            while next_page < n_pages
                && !free_slots.is_empty()
                && session.free_sq() > 0
                && in_flight < pool_n
            {
                let slot = free_slots.pop().unwrap();
                let pi = next_page;
                next_page += 1;
                let page = page_ids[pi];
                let need = g_page_need(n_bytes, page);
                if need == 0 {
                    free_slots.push(slot);
                    continue;
                }
                let off = g_off + u64::from(page) * G_PAGE_BYTES as u64;
                let buf = &mut bufs[slot][..need];
                buf.fill(0);
                let ud = crate::uring_session::pack_ud(
                    crate::uring_session::KIND_MPHF_G,
                    epoch,
                    slot as u32,
                );
                session.push_pread_flags(fd, off, buf, ud, 0)?;
                slot_page[slot] = Some(pi);
                in_flight += 1;
            }
            session.sync_submission();
            let _ = session.submit();
            if in_flight == 0 {
                break;
            }
            let mut cqes = session.harvest_ready()?;
            if cqes.is_empty() {
                session.submit_and_wait_one()?;
                cqes = session.harvest_ready()?;
                if cqes.is_empty() {
                    session.poison();
                    return Err(StoreError::Corrupt("invariant: io_uring wait timeout"));
                }
            }
            for (ud, res) in cqes {
                let (kind, ep, slot) = crate::uring_session::unpack_ud(ud);
                let slot = slot as usize;
                if kind != crate::uring_session::KIND_MPHF_G
                    || ep != epoch
                    || slot >= pool_n
                    || slot_page[slot].is_none()
                {
                    session.poison();
                    return Err(StoreError::Corrupt("invariant: io_uring leftover cqe"));
                }
                in_flight = in_flight.saturating_sub(1);
                let pi = slot_page[slot].take().unwrap();
                let page = page_ids[pi];
                let need = g_page_need(n_bytes, page);
                if res < 0 {
                    return Err(StoreError::io(
                        path,
                        std::io::Error::from_raw_os_error(-res),
                    ));
                }
                let mut n = res as usize;
                if n < need {
                    load_g_page(file, path, g_off, n_bytes, page, &mut bufs[slot])?;
                    n = need;
                }
                n = n.min(need);
                page_preads.fetch_add(1, Ordering::Relaxed);
                fill(page, &bufs[slot][..n]);
                free_slots.push(slot);
            }
        }
        Ok(())
    })();
    session.drain_all()?;
    run
}

fn g_bits_for_modulus(modulus: u32) -> u32 {
    if modulus <= 1 {
        return 1;
    }
    32 - (modulus - 1).leading_zeros()
}

fn packed_g_bytes(n_verts: u32, g_bits: u32) -> u64 {
    let bits = u64::from(n_verts) * u64::from(g_bits);
    bits.div_ceil(8)
}

fn pack_g_write<W: Write>(g: &[u32], g_bits: u32, w: &mut W) -> std::io::Result<()> {
    const PAGE: usize = 4096;
    let mask = if g_bits == 32 {
        u32::MAX
    } else {
        (1u32 << g_bits) - 1
    };
    let mut page = [0u8; PAGE];
    let mut n = 0usize;
    let mut acc = 0u64;
    let mut acc_bits = 0u32;
    for &val in g {
        acc |= u64::from(val & mask) << acc_bits;
        acc_bits += g_bits;
        while acc_bits >= 8 {
            page[n] = acc as u8;
            n += 1;
            acc >>= 8;
            acc_bits -= 8;
            if n == PAGE {
                w.write_all(&page)?;
                n = 0;
            }
        }
    }
    if acc_bits > 0 {
        page[n] = acc as u8;
        n += 1;
    }
    if n > 0 {
        w.write_all(&page[..n])?;
    }
    Ok(())
}

#[cfg(test)]
fn pack_g(g: &[u32], g_bits: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(packed_g_bytes(g.len() as u32, g_bits) as usize);
    pack_g_write(g, g_bits, &mut out).unwrap();
    out
}

fn unpack_g_at(buf: &[u8], v: u32, g_bits: u32) -> u32 {
    let start = u64::from(v) * u64::from(g_bits);
    let byte = (start / 8) as usize;
    if byte >= buf.len() {
        return 0;
    }
    extract_g_window(&buf[byte..], None, 0, (start % 8) as u32, g_bits)
}

#[cfg(test)]
fn unpack_g_bits_from_page_window(
    page: &[u8],
    next: Option<&[u8]>,
    page_id: u32,
    v: u32,
    g_bits: u32,
) -> u32 {
    let start = u64::from(v) * u64::from(g_bits);
    let start_byte = start / 8;
    let page_base = u64::from(page_id) * G_PAGE_BYTES as u64;
    if start_byte < page_base {
        return 0;
    }
    extract_g_window(
        page,
        next,
        (start_byte - page_base) as usize,
        (start % 8) as u32,
        g_bits,
    )
}

fn extract_g_window(page: &[u8], next: Option<&[u8]>, off: usize, rem: u32, g_bits: u32) -> u32 {
    let last = rem.saturating_add(g_bits.saturating_sub(1)) / 8;
    let need = (last as usize + 1).min(8);
    let mut acc = 0u64;
    for i in 0..need {
        let src = off + i;
        let b = if src < page.len() {
            page[src]
        } else {
            match next {
                Some(n) => n.get(src - page.len()).copied().unwrap_or(0),
                None => 0,
            }
        };
        acc |= u64::from(b) << (8 * i);
    }
    let mask = if g_bits >= 32 {
        u32::MAX
    } else {
        (1u32 << g_bits) - 1
    };
    ((acc >> rem) as u32) & mask
}

#[derive(Clone, Copy)]
struct GExtract {
    ki: u32,
    slot: u8,
    off: u16,
    rem: u8,
    start_page: u32,
}

fn g_extract(ki: u32, slot: u8, vert: u32, g_bits: u32) -> (u32, GExtract) {
    let start = u64::from(vert) * u64::from(g_bits);
    let start_byte = start / 8;
    let start_page = (start_byte / G_PAGE_BYTES as u64) as u32;
    let end = start + u64::from(g_bits.saturating_sub(1));
    let end_page = (end / 8 / G_PAGE_BYTES as u64) as u32;
    (
        end_page,
        GExtract {
            ki,
            slot,
            off: (start_byte % G_PAGE_BYTES as u64) as u16,
            rem: (start % 8) as u8,
            start_page,
        },
    )
}

struct GPageScatter {
    g_bits: u32,
    bucket_of: Vec<u32>,
    buckets: Vec<Vec<GExtract>>,
    tails: Vec<Option<(u16, [u8; 8])>>,
    pending: Vec<Vec<(GExtract, [u8; 8])>>,
    words: Vec<[u32; 3]>,
}

impl GPageScatter {
    fn from_verts(g_bits: u32, verts: &[[u32; 3]], page_ids: &[u32]) -> Self {
        let max_p = page_ids.iter().copied().max().unwrap_or(0) as usize;
        let mut bucket_of = vec![u32::MAX; max_p + 1];
        for (i, &p) in page_ids.iter().enumerate() {
            bucket_of[p as usize] = i as u32;
        }
        let mut buckets = vec![Vec::new(); page_ids.len()];
        for (ki, v) in verts.iter().enumerate() {
            for (slot, &vert) in v.iter().enumerate() {
                let (end_page, e) = g_extract(ki as u32, slot as u8, vert, g_bits);
                let Some(&bi) = bucket_of.get(end_page as usize) else {
                    continue;
                };
                if bi == u32::MAX {
                    continue;
                }
                buckets[bi as usize].push(e);
            }
        }
        Self {
            g_bits,
            bucket_of,
            buckets,
            tails: vec![None; page_ids.len()],
            pending: vec![Vec::new(); page_ids.len()],
            words: vec![[0u32; 3]; verts.len()],
        }
    }

    fn put(&mut self, e: GExtract, val: u32) {
        self.words[e.ki as usize][e.slot as usize] = val;
    }

    fn fill(&mut self, page: u32, buf: &[u8]) {
        let Some(&bi32) = self.bucket_of.get(page as usize) else {
            return;
        };
        if bi32 == u32::MAX {
            return;
        }
        let bi = bi32 as usize;
        let mut tail = [0u8; 8];
        let n = buf.len().min(8);
        if n > 0 {
            tail[8 - n..].copy_from_slice(&buf[buf.len() - n..]);
        }
        self.tails[bi] = Some((buf.len() as u16, tail));
        let waiters = std::mem::take(&mut self.pending[bi]);
        for (e, prefix) in waiters {
            let val = extract_g_window(
                &tail,
                Some(&prefix),
                8 + e.off as usize - buf.len(),
                e.rem as u32,
                self.g_bits,
            );
            self.put(e, val);
        }
        let extracts = std::mem::take(&mut self.buckets[bi]);
        for e in extracts {
            if e.start_page == page {
                let val = extract_g_window(buf, None, e.off as usize, e.rem as u32, self.g_bits);
                self.put(e, val);
                continue;
            }
            let Some(&sbi32) = self.bucket_of.get(e.start_page as usize) else {
                continue;
            };
            if sbi32 == u32::MAX {
                continue;
            }
            let sbi = sbi32 as usize;
            if let Some((plen, head)) = self.tails[sbi] {
                let val = extract_g_window(
                    &head,
                    Some(buf),
                    8 + e.off as usize - plen as usize,
                    e.rem as u32,
                    self.g_bits,
                );
                self.put(e, val);
            } else {
                let mut prefix = [0u8; 8];
                let pn = buf.len().min(8);
                if pn > 0 {
                    prefix[..pn].copy_from_slice(&buf[..pn]);
                }
                self.pending[sbi].push((e, prefix));
            }
        }
    }
}

fn vertex_pages(v: u32, g_bits: u32) -> impl Iterator<Item = u32> {
    let start = u64::from(v) * u64::from(g_bits);
    let end = start + u64::from(g_bits.saturating_sub(1));
    let p0 = (start / 8 / G_PAGE_BYTES as u64) as u32;
    let p1 = (end / 8 / G_PAGE_BYTES as u64) as u32;
    p0..=p1
}

#[cfg(test)]
fn vertex_straddles_page(v: u32, g_bits: u32) -> bool {
    let mut it = vertex_pages(v, g_bits);
    let a = it.next();
    let b = it.next();
    a.is_some() && b.is_some()
}

#[cfg(test)]
fn scatter_g_words(g_bits: u32, verts: &[[u32; 3]], pages: &[(u32, &[u8])]) -> Vec<[u32; 3]> {
    let mut page_ids: Vec<u32> = pages.iter().map(|&(p, _)| p).collect();
    page_ids.sort_unstable();
    page_ids.dedup();
    let mut scatter = GPageScatter::from_verts(g_bits, verts, &page_ids);
    for &(p, buf) in pages {
        scatter.fill(p, buf);
    }
    scatter.words
}

#[derive(Default)]
struct PeelScratch {
    deg: Vec<u8>,
    xor_e: Vec<u32>,
    q: Vec<u32>,
    order: Vec<(u32, u32)>,
}

impl PeelScratch {
    fn prepare(&mut self, m: usize, n: usize) {
        self.deg.clear();
        self.deg.resize(m, 0);
        self.xor_e.clear();
        self.xor_e.resize(m, 0);
        self.q.clear();
        self.order.clear();
        self.order.reserve(n);
    }
}

fn peel_order(keys: &[u64], seed: u64, m: u32, scratch: &mut PeelScratch, partite: bool) -> bool {
    let n = keys.len();
    for (i, &k) in keys.iter().enumerate() {
        let ei = i as u32;
        for v in hash_verts(k, seed, m, partite) {
            let d = &mut scratch.deg[v as usize];
            if *d == 255 {
                return false;
            }
            *d += 1;
            scratch.xor_e[v as usize] ^= ei;
        }
    }
    for (v, &d) in scratch.deg.iter().enumerate() {
        if d == 1 {
            scratch.q.push(v as u32);
        }
    }
    let mut qi = 0usize;
    while qi < scratch.q.len() {
        let v = scratch.q[qi];
        qi += 1;
        if scratch.deg[v as usize] != 1 {
            continue;
        }
        let ei = scratch.xor_e[v as usize];
        if ei as usize >= n {
            return false;
        }
        scratch.order.push((ei, v));
        for u in hash_verts(keys[ei as usize], seed, m, partite) {
            let d = &mut scratch.deg[u as usize];
            if *d == 0 {
                return false;
            }
            *d -= 1;
            scratch.xor_e[u as usize] ^= ei;
            if *d == 1 {
                scratch.q.push(u);
            }
        }
    }
    scratch.order.len() == n
}

fn assign_g(
    keys: &[u64],
    ranks: &[u32],
    seed: u64,
    m: u32,
    modulus: u32,
    order: &[(u32, u32)],
) -> Vec<u32> {
    let mut g = vec![0u32; m as usize];
    let mut assigned = vec![false; m as usize];
    for &(ei, v) in order.iter().rev() {
        let h = hash3(keys[ei as usize], seed, m);
        let mut s = 0u32;
        for u in h {
            if assigned[u as usize] {
                s = s.wrapping_add(g[u as usize]);
            }
        }
        let rank = ranks[ei as usize];
        g[v as usize] = (rank + modulus - (s % modulus)) % modulus;
        assigned[v as usize] = true;
    }
    g
}

fn compact_vertex_count(n: u32) -> u32 {
    let m = ((u64::from(n) * GAMMA_NUM + GAMMA_DEN - 1) / GAMMA_DEN)
        .max(u64::from(n) + 3)
        .max(3);
    let m = m.div_ceil(3) * 3;
    m as u32
}

fn assign_compact(keys: &[u64], seed: u64, m: u32, order: &[(u32, u32)]) -> (Vec<u32>, Box<[u64]>) {
    let mut g = vec![0u32; m as usize];
    let mut assigned = vec![false; m as usize];
    let mut occ = vec![0u64; (m as usize).div_ceil(64)];
    let part = m / 3;
    for &(ei, v) in order.iter().rev() {
        let h = hash3_partite(keys[ei as usize], seed, m);
        let i = if v < part {
            0
        } else if v < 2 * part {
            1
        } else {
            2
        };
        let mut s = 0u32;
        for u in h {
            if assigned[u as usize] {
                s = s.wrapping_add(g[u as usize]);
            }
        }
        g[v as usize] = (i + 3 - (s % 3)) % 3;
        assigned[v as usize] = true;
        occ_set(&mut occ, v);
    }
    (g, occ.into_boxed_slice())
}

fn occ_packed_bytes(m: u32) -> u64 {
    u64::from(m).div_ceil(8)
}

fn occ_set(occ: &mut [u64], v: u32) {
    occ[(v / 64) as usize] |= 1u64 << (v % 64);
}

fn write_occ(occ: &[u64], m: u32, w: &mut impl Write) -> std::io::Result<()> {
    let n = occ_packed_bytes(m) as usize;
    let mut buf = vec![0u8; n];
    for v in 0..m {
        if occ[(v / 64) as usize] & (1u64 << (v % 64)) != 0 {
            buf[(v / 8) as usize] |= 1 << (v % 8);
        }
    }
    w.write_all(&buf)
}

fn read_occ(buf: &[u8], m: u32) -> Box<[u64]> {
    let mut occ = vec![0u64; (m as usize).div_ceil(64)];
    for v in 0..m {
        let byte = buf.get((v / 8) as usize).copied().unwrap_or(0);
        if byte & (1 << (v % 8)) != 0 {
            occ_set(&mut occ, v);
        }
    }
    occ.into_boxed_slice()
}

fn popcount_range(occ: &[u64], lo: usize, hi: usize) -> u32 {
    let mut n = 0u32;
    let mut b = lo;
    while b < hi {
        let word = b / 64;
        let bit = b % 64;
        let take = (64 - bit).min(hi - b);
        let mask = if take == 64 {
            u64::MAX
        } else {
            ((1u64 << take) - 1) << bit
        };
        n += (occ.get(word).copied().unwrap_or(0) & mask).count_ones();
        b += take;
    }
    n
}

impl CompactRank {
    fn empty() -> Self {
        Self {
            m: 0,
            occ: Box::new([]),
            supers: Box::new([0]),
        }
    }

    fn from_occ(occ: Box<[u64]>, m: u32) -> Self {
        let n_supers = (m as usize).div_ceil(RANK_SUPER_BITS as usize);
        let mut supers = vec![0u32; n_supers + 1];
        let mut acc = 0u32;
        for i in 0..n_supers {
            supers[i] = acc;
            let bit0 = i * RANK_SUPER_BITS as usize;
            let bit1 = ((i + 1) * RANK_SUPER_BITS as usize).min(m as usize);
            acc += popcount_range(&occ, bit0, bit1);
        }
        supers[n_supers] = acc;
        Self {
            m,
            occ,
            supers: supers.into_boxed_slice(),
        }
    }

    fn rank1(&self, v: u32) -> u32 {
        let v = v.min(self.m);
        let si = (v / RANK_SUPER_BITS) as usize;
        let rem_lo = si * RANK_SUPER_BITS as usize;
        self.supers[si] + popcount_range(&self.occ, rem_lo, v as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bdz_injective_10k() {
        let keys: Vec<u64> = (0..10_000u64)
            .map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(7))
            .collect();
        let f = BdzMphf::build(&keys).unwrap();
        let mut seen = vec![false; keys.len()];
        for &k in &keys {
            let i = f.index(k).unwrap() as usize;
            assert!(i < keys.len());
            assert!(!seen[i], "collision at {i}");
            seen[i] = true;
        }
        assert!(seen.iter().all(|&b| b));
        let miss = f.index(0xDEAD_BEEF_u64).unwrap();
        assert!(miss < keys.len() as u32);
    }

    #[test]
    fn bdz_injective_2k() {
        let keys: Vec<u64> = (0..2_000u64)
            .map(|i| i.wrapping_mul(0xD1B5_4A32_D192_ED03).wrapping_add(11))
            .collect();
        let f = BdzMphf::build(&keys).unwrap();
        let mut seen = vec![false; keys.len()];
        for &k in &keys {
            let i = f.index(k).unwrap() as usize;
            assert!(i < keys.len());
            assert!(!seen[i], "collision at {i}");
            seen[i] = true;
        }
        assert!(seen.iter().all(|&b| b));
    }

    #[test]
    fn bdz_empty_and_one() {
        let z = BdzMphf::build(&[]).unwrap();
        assert_eq!(z.n(), 0);
        let one = BdzMphf::build(&[42]).unwrap();
        assert_eq!(one.index(42).unwrap(), 0);
        assert_eq!(one.index(99).unwrap(), 0);
    }

    #[test]
    fn bdz_roundtrip_file() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-bdz-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let keys: Vec<u64> = (0..200u64).map(|i| i * 17 + 3).collect();
        let f = BdzMphf::build(&keys).unwrap();
        let p = dir.join("t.mphf");
        f.write_to(&p).unwrap();
        assert_eq!(&std::fs::read(&p).unwrap()[0..4], b"BDZ1");
        let g = BdzMphf::read_from(&p).unwrap();
        for &k in &keys {
            assert_eq!(f.index(k).unwrap(), g.index(k).unwrap());
        }
        assert_eq!(g.g_bytes_resident(), 0, "open must not retain the g array");
        assert_eq!(g.g_bytes(), f.g_bytes());
        let miss = g.index(0xDEAD_BEEF_u64).unwrap();
        assert!(miss < keys.len() as u32);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bdz_open_matches_ram_index_without_g_heap() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-bdz-fd-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let keys: Vec<u64> = (0..10_000u64)
            .map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(7))
            .collect();
        let ram = BdzMphf::build(&keys).unwrap();
        assert!(ram.g_bytes_resident() > 0);
        let p = dir.join("t.mphf");
        ram.write_to(&p).unwrap();
        let fd = BdzMphf::read_from(&p).unwrap();
        assert_eq!(fd.g_bytes_resident(), 0);
        for &k in &keys {
            assert_eq!(ram.index(k).unwrap(), fd.index(k).unwrap());
        }
        let miss_k = 0xDEAD_BEEF_u64;
        assert_eq!(ram.index(miss_k).unwrap(), fd.index(miss_k).unwrap());
        assert!(fd.index(miss_k).unwrap() < keys.len() as u32);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn assigned_peel_index_is_rel_minus_one() {
        let keys = [10u64, 20, 30, 40];
        let rels = [3u32, 1, 4, 2];
        let values: Vec<u32> = rels.iter().map(|r| r - 1).collect();
        let f = BdzMphf::build_assigned(&keys, &values, 4).unwrap();
        assert_eq!(f.modulus(), 4);
        for (&k, &rel) in keys.iter().zip(rels.iter()) {
            assert_eq!(f.index(k).unwrap(), rel - 1);
        }
        let miss = f.index(0xDEAD_BEEF_u64).unwrap();
        assert!(miss < 4);
    }

    #[test]
    fn assigned_peel_modulus_hole_and_bip30_newest() {
        let keys = [1u64, 2, 3];
        let values = [0u32, 2, 3];
        let modulus = 4u32;
        let f = BdzMphf::build_assigned(&keys, &values, modulus).unwrap();
        assert_eq!(f.n(), 3);
        assert_eq!(f.modulus(), modulus);
        assert_eq!(f.index(1).unwrap(), 0);
        assert_eq!(f.index(2).unwrap(), 2);
        assert_eq!(f.index(3).unwrap(), 3);
        let miss = f.index(99).unwrap();
        assert!(miss < modulus);

        let newest_key = 7u64;
        let newest_rel = 5u32;
        let f2 = BdzMphf::build_assigned(&[newest_key, 8], &[newest_rel - 1, 0], 5).unwrap();
        assert_eq!(f2.index(newest_key).unwrap(), newest_rel - 1);
        assert_eq!(f2.index(8).unwrap(), 0);
        assert!(f2.index(123).unwrap() < 5);
    }

    #[test]
    fn assigned_peel_2k_permutation() {
        let n = 2_000u32;
        let keys: Vec<u64> = (0..n as u64)
            .map(|i| i.wrapping_mul(0xD1B5_4A32_D192_ED03).wrapping_add(11))
            .collect();
        let values: Vec<u32> = (0..n).map(|i| (i * 17 + 3) % n).collect();
        let mut seen = vec![false; n as usize];
        for &v in &values {
            assert!(!seen[v as usize], "test permutation");
            seen[v as usize] = true;
        }
        let f = BdzMphf::build_assigned(&keys, &values, n).unwrap();
        for (&k, &want) in keys.iter().zip(values.iter()) {
            assert_eq!(f.index(k).unwrap(), want);
        }
    }

    #[test]
    fn g_bits_for_modulus_width() {
        assert_eq!(g_bits_for_modulus(1), 1);
        assert_eq!(g_bits_for_modulus(2), 1);
        assert_eq!(g_bits_for_modulus(1 << 24), 24);
        assert_eq!(g_bits_for_modulus(1 << 25), 25);
    }

    #[test]
    fn pack_g_roundtrip_bits() {
        for g_bits in [1u32, 2, 24, 25, 26, 32] {
            let g: Vec<u32> = (0..64).map(|i| i % (1u32 << (g_bits.min(5)))).collect();
            let packed = pack_g(&g, g_bits);
            for (v, &want) in g.iter().enumerate() {
                assert_eq!(
                    unpack_g_at(&packed, v as u32, g_bits),
                    want,
                    "g_bits={g_bits} v={v}"
                );
            }
        }
    }

    #[test]
    fn unpack_g_bits_from_page_window_matches_unpack_g_at() {
        let g_bits = 25u32;
        let n = 1_400u32;
        let g: Vec<u32> = (0..n).map(|i| i.wrapping_mul(17)).collect();
        let packed = pack_g(&g, g_bits);
        assert!(packed.len() > G_PAGE_BYTES);
        let page0 = &packed[..G_PAGE_BYTES];
        let page1 = &packed[G_PAGE_BYTES..];
        let straddle = (0..n)
            .find(|&v| vertex_straddles_page(v, g_bits))
            .expect("25-bit field must cross a 4 KiB page");
        assert_eq!(
            unpack_g_bits_from_page_window(page0, Some(page1), 0, straddle, g_bits),
            unpack_g_at(&packed, straddle, g_bits),
        );
        let on_p0 = 0u32;
        assert!(!vertex_straddles_page(on_p0, g_bits));
        assert_eq!(
            unpack_g_bits_from_page_window(page0, None, 0, on_p0, g_bits),
            unpack_g_at(&packed, on_p0, g_bits),
        );
        let on_p1 = (0..n)
            .find(|&v| {
                let start = u64::from(v) * u64::from(g_bits);
                (start / 8 / G_PAGE_BYTES as u64) == 1 && !vertex_straddles_page(v, g_bits)
            })
            .expect("vertex contained in page 1");
        assert_eq!(
            unpack_g_bits_from_page_window(page1, None, 1, on_p1, g_bits),
            unpack_g_at(&packed, on_p1, g_bits),
        );
    }

    #[test]
    fn assigned_packed_fd_matches_ram_and_straddles() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-bdz2-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let n = 1_200u32;
        let modulus = 1u32 << 25;
        let keys: Vec<u64> = (0..n as u64)
            .map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(13))
            .collect();
        let values: Vec<u32> = (0..n).map(|i| i * 17 + 3).collect();
        let ram = BdzMphf::build_assigned(&keys, &values, modulus).unwrap();
        let p = dir.join("t.mphf");
        ram.write_packed_to(&p).unwrap();
        let raw = std::fs::read(&p).unwrap();
        assert_eq!(&raw[0..4], b"BDZ2");
        let fd = BdzMphf::read_packed_from(&p).unwrap();
        assert_eq!(fd.g_bytes_resident(), 0);
        assert_eq!(fd.modulus(), modulus);
        for &k in &keys {
            assert_eq!(ram.index(k).unwrap(), fd.index(k).unwrap());
        }
        let miss = 0xDEAD_BEEF_u64;
        assert_eq!(ram.index(miss).unwrap(), fd.index(miss).unwrap());
        assert!(fd.index(miss).unwrap() < modulus);

        let mut straddle_key = None;
        for &k in &keys {
            let verts = ram.vertices(k);
            let g_bits = g_bits_for_modulus(modulus);
            if verts.iter().any(|&v| vertex_straddles_page(v, g_bits)) {
                straddle_key = Some(k);
                break;
            }
        }
        let k = straddle_key.expect("expected a page-straddling vertex at 25-bit width");
        let verts = fd.vertices(k);
        let g_bits = g_bits_for_modulus(modulus);
        let mut pages: Vec<u32> = verts
            .iter()
            .copied()
            .flat_map(|v| vertex_pages(v, g_bits))
            .collect();
        pages.sort_unstable();
        pages.dedup();
        let _ = fd.take_g_page_preads();
        assert_eq!(fd.index(k).unwrap(), ram.index(k).unwrap());
        assert_eq!(fd.take_g_page_preads(), pages.len() as u64);
        assert!(
            pages.len() >= 2,
            "straddle vertex must include both page sides"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn assigned_packed_fd_index_batch_matches_ram() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-bdz2-batch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let n = 1_200u32;
        let modulus = 1u32 << 25;
        let keys: Vec<u64> = (0..n as u64)
            .map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(13))
            .collect();
        let values: Vec<u32> = (0..n).map(|i| i * 17 + 3).collect();
        let ram = BdzMphf::build_assigned(&keys, &values, modulus).unwrap();
        let p = dir.join("t.mphf");
        ram.write_packed_to(&p).unwrap();
        let fd = BdzMphf::read_packed_from(&p).unwrap();
        let g_bits = g_bits_for_modulus(modulus);
        assert!(
            keys.iter().any(|&k| ram
                .vertices(k)
                .iter()
                .any(|&v| vertex_straddles_page(v, g_bits))),
            "batch must include a page-straddling vertex"
        );
        let mut want: Vec<u32> = keys.iter().map(|&k| ram.index(k).unwrap()).collect();
        let miss = 0xDEAD_BEEF_u64;
        want.push(ram.index(miss).unwrap());
        let mut batch_keys = keys.clone();
        batch_keys.push(miss);
        let got = fd
            .index_batch(&batch_keys, &mut crate::IoCtx::none())
            .unwrap();
        assert_eq!(got, want);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn packed_g_scatter_reversed_pages_match_forward() {
        let g_bits = 25u32;
        let g: Vec<u32> = (0..3_000u32)
            .map(|i| i.wrapping_mul(17).wrapping_add(3))
            .collect();
        let packed = pack_g(&g, g_bits);
        assert!(
            packed.len() > G_PAGE_BYTES * 2,
            "need ≥3 g pages so fill order is not sequential-adjacent only"
        );
        assert!(
            (0..g.len() as u32).any(|v| vertex_straddles_page(v, g_bits)),
            "packed g must include a page-straddling vertex"
        );
        let pages: Vec<(u32, &[u8])> = packed
            .chunks(G_PAGE_BYTES)
            .enumerate()
            .map(|(i, c)| (i as u32, c))
            .collect();
        let verts: Vec<[u32; 3]> = (0..g.len() as u32).map(|v| [v, v, v]).collect();
        let want: Vec<[u32; 3]> = verts
            .iter()
            .map(|&[a, b, c]| {
                [
                    unpack_g_at(&packed, a, g_bits),
                    unpack_g_at(&packed, b, g_bits),
                    unpack_g_at(&packed, c, g_bits),
                ]
            })
            .collect();
        assert_eq!(scatter_g_words(g_bits, &verts, &pages), want);
        let mut rev = pages.clone();
        rev.reverse();
        assert_eq!(scatter_g_words(g_bits, &verts, &rev), want);
        let mut rot = pages.clone();
        rot.rotate_left(1);
        assert_eq!(scatter_g_words(g_bits, &verts, &rot), want);
    }

    #[test]
    fn assigned_packed_fd_index_batch_held_matches_ram() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-bdz2-held-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let n = 1_200u32;
        let modulus = 1u32 << 25;
        let keys: Vec<u64> = (0..n as u64)
            .map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(13))
            .collect();
        let values: Vec<u32> = (0..n).map(|i| i * 17 + 3).collect();
        let ram = BdzMphf::build_assigned(&keys, &values, modulus).unwrap();
        let p = dir.join("t.mphf");
        ram.write_packed_to(&p).unwrap();
        let fd = BdzMphf::read_packed_from(&p).unwrap();
        let mut want: Vec<u32> = keys.iter().map(|&k| ram.index(k).unwrap()).collect();
        let miss = 0xDEAD_BEEF_u64;
        want.push(ram.index(miss).unwrap());
        let mut batch_keys = keys.clone();
        batch_keys.push(miss);
        let mut session = crate::uring_session::UringSession::try_open_kind(
            crate::uring_session::SessionKind::Pool,
            32,
        )
        .expect("pool");
        let mut ctx = crate::IoCtx::held(&mut session);
        let got = fd.index_batch(&batch_keys, &mut ctx).unwrap();
        drop(ctx);
        session.drain_all().unwrap();
        assert_eq!(got, want);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compact_injective_2k() {
        let keys: Vec<u64> = (0..2_000u64)
            .map(|i| i.wrapping_mul(0xD1B5_4A32_D192_ED03).wrapping_add(11))
            .collect();
        let f = BdzMphf::build_compact(&keys).unwrap();
        let mut seen = vec![false; keys.len()];
        for &k in &keys {
            let i = f.index(k).unwrap() as usize;
            assert!(i < keys.len());
            assert!(!seen[i], "collision at {i}");
            seen[i] = true;
        }
        assert!(seen.iter().all(|&b| b));
        let miss = f.index(0xDEAD_BEEF_u64).unwrap();
        assert!(miss < keys.len() as u32);
    }

    #[test]
    fn compact_empty_and_one() {
        let z = BdzMphf::build_compact(&[]).unwrap();
        assert_eq!(z.n(), 0);
        let one = BdzMphf::build_compact(&[42]).unwrap();
        assert_eq!(one.index(42).unwrap(), 0);
        assert_eq!(one.index(99).unwrap(), 0);
    }

    #[test]
    fn compact_packed_fd_is_bdz3_and_matches_ram() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-bdz3-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let keys: Vec<u64> = (0..2_000u64)
            .map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(13))
            .collect();
        let ram = BdzMphf::build_compact(&keys).unwrap();
        let p = dir.join("t.mphf");
        ram.write_compact_to(&p).unwrap();
        let raw = std::fs::read(&p).unwrap();
        assert_eq!(&raw[0..4], b"BDZ3");
        assert_ne!(&raw[0..4], b"BDZ2");
        let g_bits = u32::from_le_bytes(raw[28..32].try_into().unwrap());
        assert_eq!(g_bits, 2);
        let fd = BdzMphf::read_compact_from(&p).unwrap();
        assert_eq!(fd.g_bytes_resident(), 0);
        assert_eq!(raw.len() as u64, ram.trailer_off());
        assert_eq!(fd.trailer_off(), ram.trailer_off());
        for &k in &keys {
            assert_eq!(ram.index(k).unwrap(), fd.index(k).unwrap());
        }
        let miss = 0xDEAD_BEEF_u64;
        assert_eq!(ram.index(miss).unwrap(), fd.index(miss).unwrap());
        assert!(fd.index(miss).unwrap() < keys.len() as u32);
        let _ = fd.take_g_page_preads();
        assert_eq!(fd.index(keys[0]).unwrap(), ram.index(keys[0]).unwrap());
        assert!(fd.take_g_page_preads() >= 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
