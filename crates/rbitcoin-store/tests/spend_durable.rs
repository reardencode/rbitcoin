use rbitcoin_store::spend_durable::*;

#[test]
fn spend_sync_due_is_ten_minutes_elapsed_only() {
    assert!(!spend_sync_due(0));
    assert!(!spend_sync_due(SPEND_DURABLE_INTERVAL_MS - 1));
    assert!(spend_sync_due(SPEND_DURABLE_INTERVAL_MS));
    assert_eq!(
        elapsed_after_checkpoint(SPEND_DURABLE_INTERVAL_MS, false),
        SPEND_DURABLE_INTERVAL_MS
    );
    assert!(spend_sync_due(elapsed_after_checkpoint(
        SPEND_DURABLE_INTERVAL_MS,
        false
    )));
    assert!(!spend_sync_due(elapsed_after_checkpoint(
        SPEND_DURABLE_INTERVAL_MS,
        true
    )));
}

#[test]
fn widen_keeps_zero_and_six_and_the_marker_span() {
    assert_eq!(widen_checkblocks(0, Some(20), Some(0)), 0);
    assert_eq!(widen_checkblocks(6, Some(9), None), 6);
    assert_eq!(widen_checkblocks(1, Some(9), Some(9)), 6);
    assert_eq!(widen_checkblocks(6, Some(9), Some(0)), 9);
    assert_eq!(widen_checkblocks(100, Some(9), Some(0)), 100);
}

#[test]
fn eight_notes_do_not_publish_and_checkpoint_keeps_the_snapshot() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-spend-notes-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let s = rbitcoin_store::Store::create_tiny(&dir).unwrap();
    let pairs: Vec<_> = (0..=7u32)
        .map(|h| (rbitcoin_primitives::Height(h), rbitcoin_primitives::Fk(1)))
        .collect();
    s.confirmed
        .set_many(&rbitcoin_store::ClassCWrite::for_test(), &pairs)
        .unwrap();
    for _ in 0..8 {
        s.note_spend_snapshot(4);
    }
    assert!(SpendDurable::load(s.path()).unwrap().is_none());

    let h = s.spend_snapshot_height().unwrap();
    s.note_spend_snapshot(7);
    s.checkpoint_spend_through(h).unwrap();
    let m = SpendDurable::load(s.path()).unwrap().unwrap();
    assert_eq!((m.annotated_through(), m.durable_through()), (4, 4));
    assert_eq!(s.spend_snapshot_height(), Some(7));

    // Tip below the snapshot: leave the marker. Disconnect clamps on its own.
    s.checkpoint_spend_through(9).unwrap();
    let m = SpendDurable::load(s.path()).unwrap().unwrap();
    assert_eq!((m.annotated_through(), m.durable_through()), (4, 4));

    let marker = s.path().join(SPEND_DURABLE_NAME);
    let _ = std::fs::remove_file(&marker);
    std::fs::create_dir(&marker).unwrap();
    let err = s.checkpoint_spend_through(4).unwrap_err();
    assert!(marker.is_dir(), "{err}");
    assert!(spend_sync_due(elapsed_after_checkpoint(
        SPEND_DURABLE_INTERVAL_MS,
        false
    )));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn clamp_drops_a_stale_height() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-spend-clamp-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let s = rbitcoin_store::Store::create_tiny(&dir).unwrap();
    s.confirmed
        .set(
            &rbitcoin_store::ClassCWrite::for_test(),
            rbitcoin_primitives::Height(0),
            rbitcoin_primitives::Fk(1),
        )
        .unwrap();
    SpendDurable::new(5, 0).store(s.path()).unwrap();
    s.clamp_spend_durable().unwrap();
    let m = SpendDurable::load(s.path()).unwrap().unwrap();
    assert_eq!((m.annotated_through(), m.durable_through()), (0, 0));
    SpendDurable::new(0, 5).store(s.path()).unwrap();
    s.clamp_spend_durable().unwrap();
    let m = SpendDurable::load(s.path()).unwrap().unwrap();
    assert_eq!((m.annotated_through(), m.durable_through()), (0, 0));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A confirm write reads its tip, then a disconnect lowers the tip and the
/// snapshot. The write's note must not raise the snapshot back over the
/// new tip, or the checkpoint publishes a height a reconnect has not
/// annotated.
#[test]
fn stale_snapshot_note_after_disconnect_stays_at_the_tip() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-spend-stale-note-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let s = rbitcoin_store::Store::create_tiny(&dir).unwrap();
    for h in 0..=7u32 {
        s.confirmed
            .set(
                &rbitcoin_store::ClassCWrite::for_test(),
                rbitcoin_primitives::Height(h),
                rbitcoin_primitives::Fk(u64::from(h) + 1),
            )
            .unwrap();
    }
    let write_read_tip = s.tip_height().unwrap().0;
    s.note_spend_snapshot(write_read_tip);
    for h in (5..=7u32).rev() {
        s.confirmed
            .disconnect_tip(
                &rbitcoin_store::ClassCWrite::for_test(),
                rbitcoin_primitives::Height(h),
            )
            .unwrap();
    }
    s.clamp_spend_durable().unwrap();
    assert_eq!(s.spend_snapshot_height(), Some(4));

    s.note_spend_snapshot(write_read_tip);
    assert_eq!(s.spend_snapshot_height(), Some(4));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A write that failed after its tip commit left heights from 5 pending.
/// The checkpoint must not publish A at or above them, whatever the
/// snapshot says, so open still replays them.
#[test]
fn checkpoint_stops_below_a_pending_annotate() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-spend-pending-ckpt-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let s = rbitcoin_store::Store::create_tiny(&dir).unwrap();
    let pairs: Vec<_> = (0..=7u32)
        .map(|h| (rbitcoin_primitives::Height(h), rbitcoin_primitives::Fk(1)))
        .collect();
    s.confirmed
        .set_many(&rbitcoin_store::ClassCWrite::for_test(), &pairs)
        .unwrap();
    s.note_spend_snapshot(7);
    s.note_spend_annotate_pending(5);
    s.checkpoint_spend_through(7).unwrap();
    let m = SpendDurable::load(s.path()).unwrap().unwrap();
    assert_eq!((m.annotated_through(), m.durable_through()), (4, 4));

    s.note_spend_annotate_pending(0);
    let _ = std::fs::remove_file(s.path().join(SPEND_DURABLE_NAME));
    s.checkpoint_spend_through(7).unwrap();
    assert!(SpendDurable::load(s.path()).unwrap().is_none());

    let token = s.spend_annotate_token();
    s.clear_spend_annotate_pending(token);
    s.checkpoint_spend_through(7).unwrap();
    let m = SpendDurable::load(s.path()).unwrap().unwrap();
    assert_eq!((m.annotated_through(), m.durable_through()), (7, 7));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A clean stem still has to `sync_data` before the marker bytes change.
/// Failing `spent` or `spenders` after the tx body has synced must leave
/// the previous file alone. `flush` on a clean file would skip that and publish.
#[test]
fn clean_replay_does_not_publish_the_marker_before_the_barrier() {
    use std::sync::atomic::Ordering;

    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-spend-barrier-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let s = rbitcoin_store::Store::create_tiny(&dir).unwrap();
    s.confirmed
        .set(
            &rbitcoin_store::ClassCWrite::for_test(),
            rbitcoin_primitives::Height(0),
            rbitcoin_primitives::Fk(1),
        )
        .unwrap();
    SpendDurable::new(4, 4).store(s.path()).unwrap();
    let marker = s.path().join(SPEND_DURABLE_NAME);
    let before = std::fs::read(&marker).unwrap();
    for file in [
        &s.txs.body.body,
        &s.txs.seqsigwit.body,
        &s.txs.spent.body,
        &s.txs.txids.file,
        &s.txs.txstat.body,
        &s.txs.txstat.ovf,
        &s.txs.txstat.blk,
        &s.txs.input.loc,
        &s.txs.input.off,
        &s.txs.input.body,
        &s.spenders.body,
    ] {
        file.needs_sync.store(false, Ordering::Release);
    }

    let spent = s.txs.spent.body.io_handle();
    rbitcoin_store::io_handle::arm_fail_sync(spent, 1);
    let arm = SyncArm(spent);
    let err = s.sync_spend_durable(0).unwrap_err();
    assert_eq!(
        std::fs::read(&marker).unwrap(),
        before,
        "spent barrier published the marker: {err}"
    );
    drop(arm);

    let spenders = s.spenders.body.io_handle();
    rbitcoin_store::io_handle::arm_fail_sync(spenders, 1);
    let arm = SyncArm(spenders);
    let err = s.sync_spend_durable(0).unwrap_err();
    assert_eq!(
        std::fs::read(&marker).unwrap(),
        before,
        "spenders barrier published the marker: {err}"
    );
    drop(arm);

    s.sync_spend_durable(0).unwrap();
    let m = SpendDurable::load(s.path()).unwrap().unwrap();
    assert_eq!((m.annotated_through(), m.durable_through()), (0, 0));
    let _ = std::fs::remove_dir_all(&dir);
}

struct SyncArm(rbitcoin_store::io_handle::IoHandle);

impl Drop for SyncArm {
    fn drop(&mut self) {
        rbitcoin_store::io_handle::disarm_sync(self.0);
    }
}

/// A replacement notes the same height after the write that is about to
/// clear. The earlier token must leave the replacement pending.
#[test]
fn stale_annotate_clear_keeps_a_later_note() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-spend-pending-token-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let s = rbitcoin_store::Store::create_tiny(&dir).unwrap();
    let old = s.note_spend_annotate_pending(5);
    let newer = s.note_spend_annotate_pending(5);
    assert_ne!(old, newer);
    s.clear_spend_annotate_pending(old);
    assert_eq!(s.spend_annotate_pending(), Some(5));
    s.clear_spend_annotate_pending(newer);
    assert_eq!(s.spend_annotate_pending(), None);
    let _ = std::fs::remove_dir_all(&dir);
}
