//! Class A append publishes locator headers before body headers.
use rbitcoin_store::file::FILE_HEADER_LEN;
use rbitcoin_store::tx_table::{InputRecord, OutputRecord, TxRecord, TxTable};

fn on_disk_hwm(file: &rbitcoin_store::file::TableFile) -> u64 {
    let mut buf = [0u8; 8];
    file.pread_all(8, &mut buf).unwrap();
    u64::from_le_bytes(buf)
}

fn one(n: u8) -> (TxRecord, Vec<InputRecord>, Vec<OutputRecord>) {
    let mut txid = [0u8; 32];
    txid[0] = n;
    (
        TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        vec![InputRecord::coinbase(u32::MAX, vec![], vec![])],
        vec![OutputRecord::unspent(1000, vec![n])],
    )
}

struct Disarm(rbitcoin_store::io_handle::IoHandle);

impl Drop for Disarm {
    fn drop(&mut self) {
        rbitcoin_store::io_handle::disarm_pwrite(self.0);
    }
}

fn set_disk_hwm(file: &rbitcoin_store::file::TableFile, len: u64) {
    file.pwrite_all(8, &len.to_le_bytes()).unwrap();
}

fn outs(t: &TxTable, fk: u64) -> Vec<rbitcoin_store::tx_table::OutputRecord> {
    t.get_meta_and_outputs(rbitcoin_primitives::Fk(fk))
        .unwrap()
        .1
}

fn numbered(n: u16) -> (TxRecord, Vec<InputRecord>, Vec<OutputRecord>) {
    let mut txid = [0u8; 32];
    txid[..2].copy_from_slice(&n.to_le_bytes());
    (
        TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        vec![InputRecord::coinbase(u32::MAX, vec![], vec![])],
        vec![OutputRecord::unspent(1000, n.to_le_bytes().to_vec())],
    )
}

/// The body high-water marks stayed at the previous create, and the locator
/// and txid counts moved. Reopen drops that unpublished create. The next
/// append does not replace the kept output.
#[test]
fn body_header_behind_the_locator_reopens_at_the_covered_prefix() {
    let dir = super::tempfile_dir("body-behind-loc");
    let t = TxTable::create_tiny(&dir).unwrap();
    t.put_full_batch_indexed(&[one(1)], false).unwrap();
    let tx_end = on_disk_hwm(&t.body.body);
    let in_end = on_disk_hwm(&t.seqsigwit.body);
    let sp_end = on_disk_hwm(&t.spent.body);
    t.put_full_batch_indexed(&[one(2)], false).unwrap();
    assert!(on_disk_hwm(&t.body.body) > tx_end);
    set_disk_hwm(&t.body.body, tx_end);
    set_disk_hwm(&t.seqsigwit.body, in_end);
    set_disk_hwm(&t.spent.body, sp_end);
    drop(t);
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 1);
    assert_eq!(outs(&t, 1)[0].script, vec![1]);
    t.put_full_batch_indexed(&[one(3)], false).unwrap();
    assert_eq!(t.count(), 2);
    assert_eq!(outs(&t, 1)[0].script, vec![1]);
    assert_eq!(outs(&t, 2)[0].script, vec![3]);
}

/// `create.loc` landed and `seqsigwit.loc` did not. Open cuts back to the
/// shorter locator instead of refusing the datadir.
#[test]
fn seqsigwit_loc_behind_create_loc_reopens_at_the_shorter_count() {
    let dir = super::tempfile_dir("seq-loc-behind");
    let t = TxTable::create_tiny(&dir).unwrap();
    t.put_full_batch_indexed(&[one(1)], false).unwrap();
    let seq_end = on_disk_hwm(&t.seqsigwit_loc.loc);
    t.put_full_batch_indexed(&[one(2)], false).unwrap();
    assert!(on_disk_hwm(&t.seqsigwit_loc.loc) > seq_end);
    set_disk_hwm(&t.seqsigwit_loc.loc, seq_end);
    drop(t);
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 1);
    assert_eq!(t.seqsigwit_loc.count(), 1);
    assert_eq!(outs(&t, 1)[0].script, vec![1]);
}

/// A 1024-create window whose `create.off` checkpoint did not land opens at
/// the last create that does not need that checkpoint.
#[test]
fn short_create_off_reopens_at_the_last_complete_window() {
    let dir = super::tempfile_dir("short-create-off");
    let t = TxTable::create_tiny(&dir).unwrap();
    let batch: Vec<_> = (1..=1024).map(numbered).collect();
    t.put_full_batch_indexed(&batch, false).unwrap();
    assert_eq!(t.create_loc.count(), 1024);
    assert!(on_disk_hwm(&t.create_loc.off) > FILE_HEADER_LEN as u64);
    set_disk_hwm(&t.create_loc.off, FILE_HEADER_LEN as u64);
    drop(t);
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 1023);
    assert_eq!(t.create_loc.count(), 1023);
    assert_eq!(outs(&t, 1)[0].script, 1u16.to_le_bytes().to_vec());
    assert_eq!(outs(&t, 1023)[0].script, 1023u16.to_le_bytes().to_vec());
    assert!(t
        .get_meta_and_outputs(rbitcoin_primitives::Fk(1024))
        .is_err());
}

/// A locator header pwrite that misses still publishes RAM, and it does not
/// store the body header. Flush keeps that old body header. The next connect
/// writes each header once and reopen sees both creates.
#[test]
fn locator_header_miss_does_not_publish_the_body_header() {
    let dir = super::tempfile_dir("loc-header-miss");
    let t = TxTable::create_tiny(&dir).unwrap();
    let loc_fd = t.create_loc.loc.io_handle();
    rbitcoin_store::io_handle::arm_fail_hwm_pwrites(loc_fd, 1);
    let disarm = Disarm(loc_fd);
    let before = FILE_HEADER_LEN as u64;
    t.put_full_batch_indexed(&[one(1)], false)
        .expect("a missed header pwrite is not a failed connect");
    drop(disarm);
    assert_eq!(t.create_loc.count(), 1);
    assert!(t.body.body_logical_len() > before);
    assert_eq!(on_disk_hwm(&t.create_loc.loc), before);
    assert_eq!(on_disk_hwm(&t.body.body), before);
    assert_eq!(on_disk_hwm(&t.seqsigwit.body), before);
    assert_eq!(on_disk_hwm(&t.spent.body), before);
    t.body.flush().unwrap();
    t.seqsigwit.flush().unwrap();
    t.spent.flush().unwrap();
    assert_eq!(
        on_disk_hwm(&t.body.body),
        before,
        "flush stored a body header the locator header does not cover"
    );
    assert_eq!(on_disk_hwm(&t.seqsigwit.body), before);
    assert_eq!(on_disk_hwm(&t.spent.body), before);
    t.body
        .with_bytes_at(before, 1, |_| Ok(()))
        .expect("in-process readers follow the RAM end");

    t.put_full_batch_indexed(&[one(2)], false).unwrap();
    assert!(on_disk_hwm(&t.create_loc.loc) > before);
    assert!(on_disk_hwm(&t.body.body) > before);
    assert!(on_disk_hwm(&t.seqsigwit.body) > before);
    assert!(on_disk_hwm(&t.spent.body) > before);
    drop(t);
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 2);
}
