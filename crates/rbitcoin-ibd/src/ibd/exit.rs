//! IBD exit / catch-up-complete decisions.
//!
//! Pure helpers so the main loop stays readable and mid-chain peer death
//! cannot be mistaken for tip mode (mainnet tip≈161k / horizon≈958k bug).

use std::time::Duration;

use super::state::IbdWorkState;

/// Max empty redial rounds while fully dark before [`Peerless::GiveUp`]
/// ends catch-up.
#[doc(hidden)]
pub const MAX_DARK_EMPTY_REDIALS: u32 = 4;

/// Longest wait between dial rounds under [`Peerless::Redial`].
pub const PEERLESS_REDIAL_CAP: Duration = Duration::from_secs(60);

/// What catch-up does when no peer is connected and a dial round finds none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peerless {
    /// Return an error after the initial dial waves or
    /// [`MAX_DARK_EMPTY_REDIALS`] dark rounds. The caller owns the retry
    /// clock.
    GiveUp,
    /// Keep dialing until a peer connects or catch-up is cancelled, as
    /// Bitcoin Core does. The wait between dark rounds doubles from 1s up
    /// to `cap`.
    Redial { cap: Duration },
}

impl Peerless {
    /// Wait before the next dial round after `dark` empty rounds in a row.
    pub fn dark_delay(self, dark: u32) -> Duration {
        match self {
            Self::GiveUp => Duration::ZERO,
            Self::Redial { .. } if dark == 0 => Duration::ZERO,
            Self::Redial { cap } => Duration::from_secs(1)
                .saturating_mul(1 << (dark - 1).min(16))
                .min(cap),
        }
    }
}

/// Highest connected best-chain height we already occupy (not competing `hash_height`).
pub fn path_high_water(st: &IbdWorkState, tip_h: u32) -> u32 {
    let h2h_hi = st.height_to_hash.highest().unwrap_or(0);
    st.max_ready_height.max(h2h_hi).max(tip_h)
}

/// How far the connected work path lags peer-advertised height.
pub fn header_lag_behind_peers(st: &IbdWorkState, tip_h: u32) -> u32 {
    st.max_peer_height
        .saturating_sub(path_high_water(st, tip_h))
}

/// `height_to_hash` already holds the connecting header at tip+1.
#[inline]
pub fn has_tip_plus_one(st: &IbdWorkState, tip_h: u32) -> bool {
    st.height_to_hash.contains_key(&tip_h.saturating_add(1))
}

#[doc(hidden)]
pub fn on_path_inflight(st: &IbdWorkState) -> bool {
    st.inflight.keys().any(|h| {
        if st.ordered_set.contains(h) {
            return true;
        }
        st.hash_height
            .get(h)
            .is_some_and(|&ht| st.is_on_path(h, ht))
    })
}

/// Work still owed to the confirmed best chain (not explore/orphan getdata).
pub fn best_chain_remainder(st: &IbdWorkState, tip_h: u32) -> bool {
    !st.ordered.is_empty()
        || st.height_to_hash.any_above(tip_h)
        || st.max_ready_height > tip_h
        || on_path_inflight(st)
}

/// WARN cadence for empty `headers` while still lagging peer horizon.
///
/// Streak must **not** be reset after log: a reset every N empties re-fires
/// `streak == 1` and floods the log when many peers reply empty in parallel.
#[inline]
pub fn should_log_empty_headers_lag(streak: u32) -> bool {
    streak == 1 || (streak > 0 && streak.is_multiple_of(64))
}

/// Re-`getheaders` cadence while lagging (one peer, round-robin) after empty replies.
#[inline]
pub fn should_rerequest_headers_on_empty_lag(streak: u32) -> bool {
    streak == 1 || (streak > 0 && streak.is_multiple_of(8))
}

/// After a non-empty `headers` that added nothing to `ordered`.
///
/// Tip chatter is 1–3 already-known hashes from every peer. `live==0` must
/// **not** re-issue getheaders on each of those (that loop was ~1k/s at
/// mainnet tip). Full 2000-header windows and real lag still advance.
pub fn should_advance_locator_after_known_batch(
    live: usize,
    lag: u32,
    full_window: bool,
    need_headroom: bool,
) -> bool {
    if live == 0 {
        return false;
    }
    full_window || lag > 2 || need_headroom
}

/// How many peers to `getheaders` when the ordered path is empty.
///
/// At path high water vs peers (`lag == 0`), or near tip with tip+1 already
/// on the path: do not fan — remaining work is getdata/BQ/confirm.
/// A connecting-header hole (peers ahead, no tip+1) always fans, including
/// `lag <= 2` (mainnet 04:14 latched `headers_done` and stopped asking).
pub fn empty_path_header_fan(st: &IbdWorkState, tip_h: u32, alive: usize) -> usize {
    let lag = header_lag_behind_peers(st, tip_h);
    if lag == 0 {
        return 0;
    }
    if lag <= 2 && has_tip_plus_one(st, tip_h) {
        return 0;
    }
    if on_path_inflight(st) {
        return 1.min(alive);
    }
    alive.clamp(1, 4)
}

/// Clear `headers_done` so empty-path `getheaders` can resume.
///
/// A proved walk at the confirmed tip does not chase a far
/// `version.start_height`, including one advertised by a connected peer.
/// One or two missing connecting headers still open. A proved walk above
/// the confirmed tip, or a latch that never proved a walk, opens for any
/// peer lead.
#[inline]
pub fn should_unlatch_headers_done(st: &IbdWorkState, tip_h: u32) -> bool {
    if !st.headers_done || !st.ordered.is_empty() {
        return false;
    }
    let lag = header_lag_behind_peers(st, tip_h);
    if lag == 0 || has_tip_plus_one(st, tip_h) {
        return false;
    }
    if st.header_walk.proved_at_or_below(tip_h) {
        return lag <= 2;
    }
    !super::header_walk::headers_complete(st, tip_h)
}

/// Full `seed_work_path_from_store` (O(header_count) walk) while empty-lagging.
///
/// Only when the ordered path is empty — a live queue already supplies locator
/// tips. Must stay rare: the walk still reads every header row. Same streak
/// cadence as [`should_log_empty_headers_lag`] so getheaders can still fan
/// out every 8.
#[inline]
pub fn should_reseed_work_path_on_empty_lag(streak: u32, ordered_empty: bool) -> bool {
    ordered_empty && should_log_empty_headers_lag(streak)
}

/// Work path idle: no ordered hashes, no on-path getdata.
///
/// Off-path leftover getdata is not drain. [`best_chain_remainder`] is the
/// exit remainder (also BQ/awaiting/h2h above tip).
#[inline]
pub fn path_drained(st: &IbdWorkState) -> bool {
    st.ordered.is_empty() && !on_path_inflight(st)
}

/// IBD densify may exit: no best-chain remainder and at the most-work path tip.
///
/// `max_peer_height` may sit far above that path (less-work high-height fork
/// or bogus `version.start_height`). Empty-EOF (`headers_done`) means we do
/// not chase that height. Neither does a proven header walk at the tip that no
/// connected peer can extend. A 2-block connecting-header hole still holds
/// exit.
#[inline]
pub fn ibd_caught_up(st: &IbdWorkState, tip_h: u32) -> bool {
    if tip_h == 0 || best_chain_remainder(st, tip_h) {
        return false;
    }
    if super::header_walk::headers_complete(st, tip_h) {
        return true;
    }
    match header_lag_behind_peers(st, tip_h) {
        0 => true,
        1 => st.headers_done,
        2 => false,
        _ => st.headers_done,
    }
}

/// Outcome when every peer slot is dead (or retained empty).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllPeersDead {
    /// Tip truly caught up — safe to exit IBD as success.
    CatchupComplete,
    /// Still mid-chain; redial in flight — keep looping.
    WaitRedial,
    /// Mid-chain and no redial hope under [`Peerless::GiveUp`] — return Err
    /// (do **not** enter tip mode).
    GiveUpMidCatchup,
}

/// Empty redial rounds in a row with no live peer. A round that adds a peer,
/// or an empty top-up while a peer is still up, starts the count over.
pub fn dark_empty_after(dark: u32, added: usize, any_alive: bool) -> u32 {
    if added > 0 || any_alive {
        0
    } else {
        dark.saturating_add(1)
    }
}

/// A live peer can always be topped up. With none, [`Peerless::GiveUp`]
/// stops dialing after [`MAX_DARK_EMPTY_REDIALS`] dark empty rounds.
pub fn may_spawn_redial(alive_n: usize, dark: u32, peerless: Peerless) -> bool {
    alive_n > 0 || matches!(peerless, Peerless::Redial { .. }) || dark < MAX_DARK_EMPTY_REDIALS
}

/// Decide what to do when `slots` has no live peers.
pub fn all_peers_dead_action(
    st: &IbdWorkState,
    tip_h: u32,
    redial_in_flight: bool,
    peerless: Peerless,
) -> AllPeersDead {
    if ibd_caught_up(st, tip_h) {
        return AllPeersDead::CatchupComplete;
    }
    if redial_in_flight || matches!(peerless, Peerless::Redial { .. }) {
        return AllPeersDead::WaitRedial;
    }
    AllPeersDead::GiveUpMidCatchup
}
