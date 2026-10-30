# 101 — Remote-limit review index

Review by bobberb and muse, 2026-10-18. This index is the status board
for the remote-request and relay items. Each fixed row names the
regression. No reproduction steps.

| Id | Severity | Topic | Status | Regression |
|----|----------|--------|--------|------------|
| D1 | medium | Orphan promotion recurses down the parked chain | fixed | `orphan_chain_promotes_to_the_cluster_cap`, `parked_chain_promotes_in_one_frame`, `package_inside_promote_admits_parent_orphans` ([092](./092-orphan-promote-stack.md)) |
| D2 | — | Declared vector length preallocates | false | rust-bitcoin 0.32.102 caps `MAX_VEC_SIZE` at 4,000,000 |
| D3 | high | History catch-up scans every block in the window | fixed | `history_window_wider_than_eight_weeks_is_refused` ([093](./093-history-window.md)) |
| D4 | high | Electrum writes have no deadline | fixed | `stalled_electrum_write_is_closed`, `stalled_scripthash_push_ends_the_connection` ([094](./094-electrum-write-deadline.md)) |
| D5 | high | SV2 session has no idle deadline after setup | opt-in | `session_silent_after_constraints_is_dropped_at_the_idle_deadline` ([095](./095-sv2-idle-deadline.md)) |
| D6 | — | Replacement feerate uses the full descendant set | won't-fix | Direct-set pricing stays. See [051](./051-rbfr-direct-set.md) |
| D7 | medium | Replacement may add an unconfirmed input | fixed | `replacement_unconfirmed_inputs_follow_libre_rule` ([096](./096-unconfirmed-rbf-input.md)) |
| D8 | low | Invalid-txid set clears at 4096 | fixed | `recent_invalid_keeps_the_oldest` ([097](./097-recent-invalid-cap.md)) |
| D9 | medium | Overlay misbehavior is not remembered | fixed | `overlay_misbehavior_discourages_that_net`, `overlay_refusal_ignores_the_port`, `slot_evict_does_not_block_an_outbound_dial`, `feeler_does_not_dial_a_discouraged_address`, `ibd_dial_refuses_a_discouraged_net` ([098](./098-overlay-discourage.md)) |
| D10 | medium | GET /broadcast has no Origin check | fixed | `esplora_unix_internal` ([099](./099-esplora-get-broadcast.md)) |
| D11 | — | Default history ignores the create cap | partial | The open window is [093](./093-history-window.md). One-argument history stays under `--max-sh-creates` |
| D12 | — | Constraint rebuilds are unbounded | won't-fix | The 1s cooldown is the limit (`template_constraint_rebuilds_are_rate_limited`) |
| D13 | medium | Script-pool panic sticks the wave | fixed | `chunk_panic_releases_the_wave` ([100](./100-script-pool-panic.md)) |
