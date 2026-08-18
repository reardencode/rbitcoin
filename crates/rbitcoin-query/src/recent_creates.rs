//! Height-FIFO identity ring: just-confirmed `txid → (create_fk, body_range)`.
//!
//! Write publishes after Class A + idx. Load stamp probes this **after**
//! published live-union and **before** leftover TipOnly. Outs are not stored
//! (not a process pin FIFO).
//!
//! Expire is `pop_front` of whole heights. Horizon is
//! [`recent_creates_horizon`] (`2 * soft_win`, floor 256) so the ring outlives
//! BQ / lookup lead (1× the soft 1-min window is not enough).
//!
//! Writers rebuild an [`arc_swap::ArcSwap`] snapshot once per note/expire.
//! Load `get` is a pointer load, not a lock per leftover key.

use crate::published_ids::TxidHasher;
use arc_swap::ArcSwap;
use rbitcoin_primitives::Fk;
use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasherDefault;
use std::sync::{Arc, Mutex};

/// Floor so a cold / tiny `soft_win` still covers a short lookup lead.
pub const RECENT_CREATES_HORIZON_FLOOR: u32 = 256;

/// Heights to retain: twice the 1-min confirm window, at least
/// [`RECENT_CREATES_HORIZON_FLOOR`].
#[inline]
pub fn recent_creates_horizon(soft_win: u32) -> u32 {
    soft_win.saturating_mul(2).max(RECENT_CREATES_HORIZON_FLOOR)
}

type LiveMap = HashMap<[u8; 32], LiveEnt, BuildHasherDefault<TxidHasher>>;

#[derive(Clone, Copy)]
struct LiveEnt {
    fk: Fk,
    range: (u64, u64),
    height: u32,
}

struct Inner {
    live: LiveMap,
    fifo: VecDeque<(u32, Vec<[u8; 32]>)>,
}

/// Immutable live map for one stamp pack.
#[derive(Clone)]
pub struct RecentSnap(std::sync::Arc<LiveMap>);

impl RecentSnap {
    pub fn get(&self, txid: &[u8; 32]) -> Option<(Fk, (u64, u64))> {
        if *txid == [0u8; 32] {
            return None;
        }
        self.0.get(txid).map(|e| (e.fk, e.range))
    }
}

/// Write-published, load-read identity ring.
pub struct RecentCreates {
    live: ArcSwap<LiveMap>,
    inner: Mutex<Inner>,
}

impl Default for RecentCreates {
    fn default() -> Self {
        Self {
            live: ArcSwap::from_pointee(LiveMap::default()),
            inner: Mutex::new(Inner {
                live: LiveMap::default(),
                fifo: VecDeque::new(),
            }),
        }
    }
}

impl RecentCreates {
    pub fn new() -> Self {
        Self::default()
    }

    fn publish(live: &ArcSwap<LiveMap>, g: &Inner) {
        live.store(Arc::new(g.live.clone()));
    }

    /// Insert creates at `height`. Last write wins if the txid is already live.
    pub fn note(&self, height: u32, rows: impl IntoIterator<Item = ([u8; 32], Fk, (u64, u64))>) {
        let mut keys: Vec<[u8; 32]> = Vec::new();
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        for (txid, fk, range) in rows {
            if txid == [0u8; 32] {
                continue;
            }
            g.live.insert(txid, LiveEnt { fk, range, height });
            keys.push(txid);
        }
        if keys.is_empty() {
            return;
        }
        g.fifo.push_back((height, keys));
        Self::publish(&self.live, &g);
    }

    /// Drop heights `≤ through` (inclusive). A key stays if a newer height
    /// re-noted it (last-write `LiveEnt.height`).
    pub fn expire_through(&self, through: u32) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut changed = false;
        while let Some(&(h, _)) = g.fifo.front() {
            if h > through {
                break;
            }
            let (_, keys) = g.fifo.pop_front().expect("front");
            for t in keys {
                if let Some(ent) = g.live.get(&t) {
                    if ent.height <= through {
                        g.live.remove(&t);
                        changed = true;
                    }
                }
            }
        }
        if changed {
            Self::publish(&self.live, &g);
        }
    }

    /// Forget heights `≤ tip − horizon`. No-op while `tip < horizon` so a
    /// genesis-height note is not dropped on the first packs.
    pub fn expire_to_horizon(&self, tip: u32, horizon: u32) {
        if tip < horizon {
            return;
        }
        self.expire_through(tip - horizon);
    }

    /// Disconnect: drop heights `≥ height`.
    pub fn drop_from(&self, height: u32) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let before = g.live.len();
        g.fifo.retain(|(h, _)| *h < height);
        g.live.retain(|_, ent| ent.height < height);
        if g.live.len() != before {
            Self::publish(&self.live, &g);
        }
    }

    /// Point get. Zero txid is never a hit. Lock-free snapshot load.
    pub fn get(&self, txid: &[u8; 32]) -> Option<(Fk, (u64, u64))> {
        self.snapshot().get(txid)
    }

    /// One Arc for a stamp pack (do not `load` per parent).
    pub fn snapshot(&self) -> RecentSnap {
        RecentSnap(self.live.load_full())
    }

    /// Occupancy for `ibd: sizes`.
    pub fn size_snapshot(&self) -> (usize, usize) {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        (g.fifo.len(), g.live.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid(b: u8) -> [u8; 32] {
        let mut t = [0u8; 32];
        t[0] = b;
        t
    }

    #[test]
    fn recent_creates_horizon_is_2x_soft_win_with_floor() {
        assert_eq!(recent_creates_horizon(0), RECENT_CREATES_HORIZON_FLOOR);
        assert_eq!(recent_creates_horizon(100), RECENT_CREATES_HORIZON_FLOOR);
        assert_eq!(recent_creates_horizon(200), 400);
        assert_eq!(recent_creates_horizon(400), 800);
    }

    #[test]
    fn note_makes_get_visible() {
        let r = RecentCreates::new();
        assert!(r.get(&tid(1)).is_none());
        r.note(10, [(tid(1), Fk(7), (100, 8))]);
        assert_eq!(r.get(&tid(1)), Some((Fk(7), (100, 8))));
        assert!(r.get(&tid(2)).is_none());
    }

    #[test]
    fn zero_txid_is_never_a_hit() {
        let r = RecentCreates::new();
        r.note(1, [([0u8; 32], Fk(1), (0, 1))]);
        assert!(r.get(&[0u8; 32]).is_none());
        assert_eq!(r.size_snapshot(), (0, 0));
    }

    #[test]
    fn expire_through_drops_old_keeps_newer() {
        let r = RecentCreates::new();
        r.note(10, [(tid(1), Fk(1), (1, 2)), (tid(2), Fk(2), (3, 4))]);
        r.note(11, [(tid(2), Fk(2), (3, 4)), (tid(3), Fk(3), (5, 6))]);
        r.expire_through(10);
        assert!(r.get(&tid(1)).is_none(), "height-10-only key must drop");
        assert_eq!(
            r.get(&tid(2)),
            Some((Fk(2), (3, 4))),
            "re-noted at 11 must survive expire of 10"
        );
        assert_eq!(r.get(&tid(3)), Some((Fk(3), (5, 6))));
        let (heights, keys) = r.size_snapshot();
        assert_eq!(heights, 1);
        assert_eq!(keys, 2);
    }

    #[test]
    fn expire_to_horizon_keeps_until_tip_covers_window() {
        let r = RecentCreates::new();
        r.note(0, [(tid(1), Fk(1), (1, 2))]);
        r.expire_to_horizon(100, RECENT_CREATES_HORIZON_FLOOR);
        assert_eq!(
            r.get(&tid(1)),
            Some((Fk(1), (1, 2))),
            "tip below horizon must not drop genesis-height notes"
        );
        r.expire_to_horizon(RECENT_CREATES_HORIZON_FLOOR, RECENT_CREATES_HORIZON_FLOOR);
        assert!(r.get(&tid(1)).is_none());
    }

    #[test]
    fn drop_from_removes_disconnect_height_and_above() {
        let r = RecentCreates::new();
        r.note(10, [(tid(1), Fk(1), (1, 2))]);
        r.note(12, [(tid(2), Fk(2), (3, 4))]);
        r.drop_from(12);
        assert_eq!(r.get(&tid(1)), Some((Fk(1), (1, 2))));
        assert!(r.get(&tid(2)).is_none());
    }
}
