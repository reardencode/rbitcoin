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
