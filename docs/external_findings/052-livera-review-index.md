# 052 — Livera review index

Review by Stephan Livera, 2026-10-02, commit `058adb8d`. This index is
the status board. Each fixed row names the regression. No reproduction
steps.

| Id | Severity | Topic | Status | Regression |
|----|----------|--------|--------|------------|
| C1 | critical | Unbounded parent-request tracker | fixed | `parent_req_stops_at_per_peer_cap`, `parent_req_stops_at_global_cap`, `second_peer_take_due_does_not_drop_other_peers_keys` ([053](./053-parent-req-cap.md)) |
| N2 | low | Wtxid follow-up requested as a txid | fixed | `wtxid_followup_is_requested_as_wtx` ([054](./054-wtxid-getdata.md)) |
| H1 | high | Decoy and invalid-type packets skip the rate window | fixed | `decoy_packet_is_handed_to_the_rate_hook` ([055](./055-decoy-rate.md)) |
| H2 | high | Inbound eviction drops the longest-connected peer | fixed | `eviction_drops_the_newest_in_the_largest_netgroup` ([060](./060-evict-newest-netgroup.md)) |
| H2-ban | high | Misbehavior disconnect is not remembered | fixed | `misbehavior_disconnect_refuses_the_same_address` ([061](./061-misbehavior-remembered.md)) |
| H3 | high | REST always on and shares the RPC work queue | fixed | `rest_is_404_without_the_flag` ([063](./063-rest-own-queue.md)) |
| H4 | medium | Silent-payment unsubscribe logs the scan secret | fixed | `api_call_redacts_scan_secrets_and_ext_privkeys` ([064](./064-api-log-redaction.md)) |
| H5 | high | IBD reader credits unsolicited data as progress | fixed | `unsolicited_block_does_not_refresh_progress` ([062](./062-ibd-requested-progress.md)) |
| N1 | medium | Inv getdata does not charge the send budget | fixed | `inv_getdata_charges_send_budget` ([056](./056-inv-getdata-budget.md)) |
| M1 | medium | Block getdata can queue past the send budget | fixed | `getdata_stops_when_send_budget_is_already_over` ([057](./057-block-getdata-budget.md)) |
| M2 | medium | Silent-payment scan span is unbounded when start is set | fixed | `parse_sub_labels_start_and_networks`, `sp_scan_stops_when_the_client_hangs_up` ([065](./065-sp-scan-window.md)) |
| M3 | medium | RPC listener has no accept timeout; long-poll holds a permit | fixed | `long_poll_does_not_hold_the_work_queue`, `wait_timeout_ms_caps_at_two_minutes` ([066](./066-rpc-wait-cap.md)) |
| M4 | medium | fuse8 segment length need not be a power of two | fixed | `fuse8_segment_length_must_be_power_of_two` ([067](./067-fuse8-segment.md)) |
| M5 | medium | Class A bulk read ignores the published end | fixed | `body_read_past_published_end_is_corrupt`, `create_loc_read_past_published_end_is_corrupt`, `body_read_uses_the_caller_published_end`, `create_loc_window_read_uses_the_planned_published_end` ([068](./068-published-end.md)) |
| M6 | medium | Testnet milestone is height-only | fixed | `p3_default_milestone_heights`, `operator_conf_and_argv` ([073](./073-testnet-milestone-scripts.md)) |
| M7 | medium | Mempool inv is one message per transaction | fixed | `tx_inv_over_one_thousand_is_two_messages` ([058](./058-tx-inv-batch.md)) |
| M8 | medium | Pending blocks and orphans are count-capped only | fixed | `pending_block_over_four_megabytes_is_not_parked`, `one_peer_cannot_fill_the_orphanage` ([074](./074-tip-body-orphan-bytes.md)) |
| M9 | high | io_uring drop can free a buffer the kernel still owns | fixed | `drain_guard_drop_with_leftover_pending_does_not_abort` ([069](./069-uring-drop-drain.md)) |
| M10 | low | Secret types derive Debug; create-then-chmod | fixed | `debug_does_not_print_secret_bytes`, `debug_does_not_print_the_token` ([075](./075-secret-debug.md)) |
| L1 | low | Height-0 BIP68 time lock uses median time 0 | fixed | `bip68_height_zero_time_lock_uses_the_median` ([076](./076-bip68-genesis-median.md)) |
| L4 | low | Empty median time panics | fixed | `empty_median_time_is_an_error` ([077](./077-empty-median.md)) |
| L5 | low | Version nonce is not a CSPRNG | fixed | `rand_nonce_changes` ([078](./078-version-nonce.md)) |
| L6 | low | Recent-reject set clears at the cap | fixed | `recent_reject_at_the_cap_does_not_clear` ([079](./079-recent-reject-cap.md)) |
| L8 | low | Manifest and txstat lengths allocate before a size check | fixed | `manifest_length_past_the_file_is_corrupt`, `txstat_blob_longer_than_the_file_is_corrupt` ([070](./070-manifest-length.md)) |
| L9 | low | Tor control password on argv | fixed | `tor_control_password_rejects_a_line_break` ([080](./080-tor-control-password.md)) |
| L10 | low | Datadir lock follows a symlink | fixed | `lock_file_does_not_follow_a_symlink` ([071](./071-datadir-lock-symlink.md)) |
| L11 | low | Conf parse errors echo the raw line | fixed | `conf_error_names_the_file_and_line` ([081](./081-conf-error-line.md)) |
| L12 | low | Invalid-hash set grows without a cap | fixed | `invalid_hash_set_stops_at_the_cap` ([082](./082-invalid-hash-cap.md)) |
| L13 | low | Rate window grants two budgets at the boundary | fixed | `rate_limiter_boundary_does_not_grant_a_second_budget` ([059](./059-rate-window-boundary.md)) |
| L14 | low | Mempool expiry runs only on admission | fixed | `expire_stale_drops_old_tx_without_a_new_accept`, `hub_live_journey` ([083](./083-mempool-expiry-cursor.md)) |
| L15 | low | Write jobs form a mutable slice over a shared buffer | fixed | pool write arm uses a shared slice ([072](./072-pool-write-slice.md)) |
| L2 | — | P2PKH fast path skips FindAndDelete | rejected | The fast path is the 25-byte template. A DER signature does not fit in that scriptCode, so FindAndDelete cannot change it. |
| L3 | — | Witness-v0 strict DER independent of BIP66 | rejected | BIP141 witness verification is strict DER. Mainnet, testnet, signet, and regtest are unaffected. |
| L7 | low | Rewind deeper than 1024 is refused | won't-fix | `REWIND_MAX_DEPTH` is a deliberate denial-of-service cap. Removing it needs an operator decision. No new knob. |
| L16 | — | Warnet image is pinned by tag | won't-fix | `scripts/core-functional/warnet/Dockerfile` is a lab image, not a Release. |
| eclipse | — | Inverted eviction eclipses the node | rejected | Outbound peers are not eviction candidates. The defect is inbound-slot monopoly, tracked as H2. |
| M2-sh | — | Silent-payment subscribe must require `--sh-index` | rejected | The scan uses the tweak index, not the scripthash index (finding 036). |
| M8-fee | — | Fee and sigop checks at orphan park | rejected | The parent outputs are not available yet. Shape checks already run before park. |
| M6-flag | — | Height-only `--milestone` needs a new flag | rejected | Explicit `--milestone HEIGHT` is already that switch (finding 042). |

Owner: [`quality.md`](../quality.md) **Q-72**.
