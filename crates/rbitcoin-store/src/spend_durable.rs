//! Sidecar for heights whose spend annotations and Class A bodies are durable.
//!
//! Not a [`SCHEMA_VERSION`](rbitcoin_primitives::SCHEMA_VERSION) bump. A missing
//! file means nothing has been synced yet.

use crate::error::StoreError;
use crate::file::write_synced_tmp_rename;
use rbitcoin_primitives::{schema_file_openable, SCHEMA_VERSION, STORE_MAGIC};
use std::path::Path;

/// `store/spend_durable`. Annotated-through and durable-through heights.
pub const SPEND_DURABLE_NAME: &str = "spend_durable";

/// Wall time between spend `sync_data` checkpoints. Not a knob.
pub const SPEND_DURABLE_INTERVAL_MS: u64 = 600_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SpendDurable {
    annotated_through: u32,
    durable_through: u32,
}

impl SpendDurable {
    pub(crate) fn new(annotated_through: u32, durable_through: u32) -> Self {
        Self {
            annotated_through,
            durable_through,
        }
    }

    pub(crate) fn annotated_through(self) -> u32 {
        self.annotated_through
    }

    pub(crate) fn durable_through(self) -> u32 {
        self.durable_through
    }

    pub(crate) fn load(dir: &Path) -> Result<Option<Self>, StoreError> {
        let path = dir.join(SPEND_DURABLE_NAME);
        if !path.exists() {
            return Ok(None);
        }
        let buf = std::fs::read(&path).map_err(|e| StoreError::io(&path, e))?;
        if buf.len() != 16 {
            return Err(StoreError::Corrupt("spend_durable short"));
        }
        if buf[0..4] != STORE_MAGIC {
            return Err(StoreError::BadMagic);
        }
        let ver = u16::from_le_bytes(buf[4..6].try_into().unwrap());
        if !schema_file_openable(ver) {
            return Err(StoreError::BadSchema(ver));
        }
        Ok(Some(Self {
            annotated_through: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            durable_through: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
        }))
    }

    pub(crate) fn store(&self, dir: &Path) -> Result<(), StoreError> {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&STORE_MAGIC);
        buf[4..6].copy_from_slice(&SCHEMA_VERSION.to_le_bytes());
        buf[8..12].copy_from_slice(&self.annotated_through.to_le_bytes());
        buf[12..16].copy_from_slice(&self.durable_through.to_le_bytes());
        write_synced_tmp_rename(&dir.join(SPEND_DURABLE_NAME), &buf)
    }
}

#[cfg(test)]
pub(crate) fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// True when a spend checkpoint is due. Batch count is not an input.
pub fn spend_sync_due(elapsed_ms: u64) -> bool {
    elapsed_ms >= SPEND_DURABLE_INTERVAL_MS
}

/// A failed publish does not start a new interval.
pub fn elapsed_after_checkpoint(elapsed_ms: u64, published: bool) -> u64 {
    if published {
        0
    } else {
        elapsed_ms
    }
}

/// `n == 0` stays "whole chain". A missing marker keeps `n`. Otherwise the
/// window is at least six and reaches back to `durable_through`.
pub(crate) fn widen_checkblocks(n: u32, tip: Option<u32>, durable_through: Option<u32>) -> u32 {
    if n == 0 {
        return 0;
    }
    let (Some(tip), Some(d)) = (tip, durable_through) else {
        return n;
    };
    let span = tip.saturating_sub(d);
    n.max(crate::VERIFY_TIP_BLOCKS).max(span)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let s = crate::Store::create_tiny(&dir).unwrap();
        s.confirmed
            .set(rbitcoin_primitives::Height(7), rbitcoin_primitives::Fk(1))
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
        let s = crate::Store::create_tiny(&dir).unwrap();
        s.confirmed
            .set(rbitcoin_primitives::Height(0), rbitcoin_primitives::Fk(1))
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
        let s = crate::Store::create_tiny(&dir).unwrap();
        for h in 0..=7u32 {
            s.confirmed
                .set(
                    rbitcoin_primitives::Height(h),
                    rbitcoin_primitives::Fk(u64::from(h) + 1),
                )
                .unwrap();
        }
        let write_read_tip = s.tip_height().unwrap().0;
        s.note_spend_snapshot(write_read_tip);
        for h in (5..=7u32).rev() {
            s.confirmed
                .disconnect_tip(rbitcoin_primitives::Height(h))
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
        let s = crate::Store::create_tiny(&dir).unwrap();
        s.confirmed
            .set(rbitcoin_primitives::Height(7), rbitcoin_primitives::Fk(1))
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

        s.clear_spend_annotate_pending();
        s.checkpoint_spend_through(7).unwrap();
        let m = SpendDurable::load(s.path()).unwrap().unwrap();
        assert_eq!((m.annotated_through(), m.durable_through()), (7, 7));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
