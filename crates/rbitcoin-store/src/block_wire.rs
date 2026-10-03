//! Bitcoin **block** wire walk: Σ `tx.input` without a `Block` decode.
//!
//! Peer enqueue stamps this so IBD lookup can pack/hold waves from the BQ
//! index. The walk refuses the payloads lookup's block decode refuses, so
//! intake can drop a body that lookup would never decode.

use rbitcoin_primitives::read_compact_size;

const HEADER_LEN: usize = 80;

/// Σ input count over every tx in a serialized block (header + tx vector).
///
/// `None` when lookup's block decode fails on a P2P-sized payload:
/// truncation, a non-minimal CompactSize, a segwit flag other than 0 or 1,
/// or a segwit tx whose witnesses are all empty. Flag 0 is Core's 10-byte
/// tx with no inputs and no outputs. Trailing bytes are ignored, as in that
/// decode.
pub fn block_wire_input_count(payload: &[u8]) -> Option<u32> {
    if payload.len() < HEADER_LEN {
        return None;
    }
    let mut off = HEADER_LEN;
    let n_tx = read_count(payload, &mut off)?;
    // A serialized tx is at least 10 bytes (version, two counts, locktime).
    if n_tx as usize > (payload.len() - off) / 10 {
        return None;
    }
    let mut inputs = 0u32;
    for _ in 0..n_tx {
        inputs = inputs.saturating_add(skip_tx(payload, &mut off)?);
    }
    Some(inputs)
}

fn read_compact(buf: &[u8], off: &mut usize) -> Option<u64> {
    let (v, n) = read_compact_size(buf.get(*off..)?).ok()?;
    // rust-bitcoin refuses a non-minimal CompactSize.
    let min = match n {
        3 => 0xfd,
        5 => 0x1_0000,
        9 => 0x1_0000_0000,
        _ => 0,
    };
    if v < min {
        return None;
    }
    *off += n;
    Some(v)
}

fn read_count(buf: &[u8], off: &mut usize) -> Option<u32> {
    u32::try_from(read_compact(buf, off)?).ok()
}

fn advance(buf: &[u8], off: &mut usize, n: usize) -> Option<()> {
    *off = off.checked_add(n)?;
    (*off <= buf.len()).then_some(())
}

fn skip_compact_blob(buf: &[u8], off: &mut usize) -> Option<()> {
    let len = usize::try_from(read_compact(buf, off)?).ok()?;
    advance(buf, off, len)
}

fn skip_input(buf: &[u8], off: &mut usize) -> Option<()> {
    advance(buf, off, 36)?;
    skip_compact_blob(buf, off)?;
    advance(buf, off, 4)
}

fn skip_output(buf: &[u8], off: &mut usize) -> Option<()> {
    advance(buf, off, 8)?;
    skip_compact_blob(buf, off)
}

/// Skip one tx; return its `nIn`.
fn skip_tx(buf: &[u8], off: &mut usize) -> Option<u32> {
    advance(buf, off, 4)?;
    let mut n_in = read_count(buf, off)?;
    let segwit = n_in == 0;
    if segwit {
        // BIP144: an empty vin is the marker and flag 1 follows. Core reads
        // flag 0 as a tx with no inputs and no outputs, then the locktime.
        match *buf.get(*off)? {
            0 => {
                advance(buf, off, 5)?;
                return Some(0);
            }
            1 => *off += 1,
            _ => return None,
        }
        n_in = read_count(buf, off)?;
    }
    for _ in 0..n_in {
        skip_input(buf, off)?;
    }
    let n_out = read_count(buf, off)?;
    for _ in 0..n_out {
        skip_output(buf, off)?;
    }
    if segwit {
        let mut any_stack = false;
        for _ in 0..n_in {
            let n_stack = read_count(buf, off)?;
            any_stack |= n_stack > 0;
            for _ in 0..n_stack {
                skip_compact_blob(buf, off)?;
            }
        }
        // rust-bitcoin refuses the segwit flag when every witness is empty.
        if n_in > 0 && !any_stack {
            return None;
        }
    }
    advance(buf, off, 4)?;
    Some(n_in)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> Vec<u8> {
        vec![0u8; HEADER_LEN]
    }

    fn compact(n: u64) -> Vec<u8> {
        let mut o = Vec::new();
        rbitcoin_primitives::write_compact_size(&mut o, n);
        o
    }

    fn coinbase_tx(n_in: u32) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&1u32.to_le_bytes());
        t.extend_from_slice(&compact(u64::from(n_in)));
        for _ in 0..n_in {
            t.extend_from_slice(&[0u8; 32]);
            t.extend_from_slice(&u32::MAX.to_le_bytes());
            t.extend_from_slice(&compact(2));
            t.extend_from_slice(&[0, 0]);
            t.extend_from_slice(&u32::MAX.to_le_bytes());
        }
        t.extend_from_slice(&compact(1));
        t.extend_from_slice(&0u64.to_le_bytes());
        t.extend_from_slice(&compact(1));
        t.push(0x51);
        t.extend_from_slice(&0u32.to_le_bytes());
        t
    }

    fn witness_tx(n_in: u32) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&1u32.to_le_bytes());
        t.push(0);
        t.push(1);
        t.extend_from_slice(&compact(u64::from(n_in)));
        for _ in 0..n_in {
            t.extend_from_slice(&[0u8; 32]);
            t.extend_from_slice(&0u32.to_le_bytes());
            t.extend_from_slice(&compact(0));
            t.extend_from_slice(&u32::MAX.to_le_bytes());
        }
        t.extend_from_slice(&compact(1));
        t.extend_from_slice(&1u64.to_le_bytes());
        t.extend_from_slice(&compact(1));
        t.push(0x51);
        for _ in 0..n_in {
            t.extend_from_slice(&compact(1));
            t.extend_from_slice(&compact(1));
            t.push(0x51);
        }
        t.extend_from_slice(&0u32.to_le_bytes());
        t
    }

    fn block(txs: &[Vec<u8>]) -> Vec<u8> {
        let mut p = header();
        p.extend_from_slice(&compact(txs.len() as u64));
        for t in txs {
            p.extend_from_slice(t);
        }
        p
    }

    #[test]
    fn header_only_and_truncated_are_none() {
        assert_eq!(block_wire_input_count(&[]), None);
        assert_eq!(block_wire_input_count(&header()), None);
        let mut p = block(&[coinbase_tx(1)]);
        p.pop();
        assert_eq!(block_wire_input_count(&p), None);
    }

    #[test]
    fn empty_tx_vector_and_trailing_bytes() {
        assert_eq!(block_wire_input_count(&block(&[])), Some(0));
        let mut p = block(&[coinbase_tx(1)]);
        p.push(0xff);
        assert_eq!(block_wire_input_count(&p), Some(1));
    }

    #[test]
    fn coinbase_and_multi_input() {
        assert_eq!(block_wire_input_count(&block(&[coinbase_tx(1)])), Some(1));
        assert_eq!(
            block_wire_input_count(&block(&[coinbase_tx(1), coinbase_tx(3)])),
            Some(4)
        );
    }

    #[test]
    fn witness_flag_counts_vin_not_stack() {
        assert_eq!(block_wire_input_count(&block(&[witness_tx(2)])), Some(2));
        assert_eq!(
            block_wire_input_count(&block(&[coinbase_tx(1), witness_tx(2)])),
            Some(3)
        );
    }

    #[test]
    fn huge_ntx_compactsize_is_none() {
        let mut p = header();
        p.extend_from_slice(&compact(u64::from(u32::MAX)));
        assert_eq!(block_wire_input_count(&p), None);
    }

    #[test]
    fn flag_zero_tx_is_ten_bytes_without_inputs() {
        let dummy = vec![1, 0, 0, 0, 0x00, 0x00, 0, 0, 0, 0];
        let p = block(&[coinbase_tx(1), dummy.clone(), coinbase_tx(2)]);
        assert_eq!(block_wire_input_count(&p), Some(3));
        let mut short = block(&[dummy]);
        short.pop();
        assert_eq!(block_wire_input_count(&short), None);
    }

    #[test]
    fn refuses_what_rust_bitcoin_refuses() {
        let mut flag2 = witness_tx(1);
        flag2[5] = 2;
        assert_eq!(block_wire_input_count(&block(&[flag2])), None);

        let mut bare = witness_tx(1);
        let lock = bare.len() - 4;
        bare.splice(lock - 3..lock, [0u8]);
        assert_eq!(block_wire_input_count(&block(&[bare])), None);

        let mut wide = header();
        wide.extend_from_slice(&[0xfd, 0x01, 0x00]);
        wide.extend_from_slice(&coinbase_tx(1));
        assert_eq!(block_wire_input_count(&wide), None);
    }
}
