# 052 — Livera review index

Review by Stephan Livera, 2026-10-02, commit `058adb8d`. This index is
the status board. Each fixed row names the regression. No reproduction
steps.

| Id | Severity | Topic | Status | Regression |
|----|----------|--------|--------|------------|
| C1 | critical | Unbounded parent-request tracker | fixed | `parent_req_stops_at_per_peer_cap`, `parent_req_stops_at_global_cap`, `second_peer_take_due_does_not_drop_other_peers_keys` ([053](./053-parent-req-cap.md)) |
| N2 | low | Wtxid follow-up requested as a txid | fixed | `wtxid_followup_is_requested_as_wtx` ([054](./054-wtxid-getdata.md)) |
| H1 | high | Decoy and invalid-type packets skip the rate window | fixed | `decoy_packet_is_handed_to_the_rate_hook` ([055](./055-decoy-rate.md)) |
| H2 | high | Inbound eviction drops the longest-connected peer | open | — |
| H2-ban | high | Misbehavior disconnect is not remembered | open | — |
| H3 | high | REST always on and shares the RPC work queue | open | — |
| H4 | medium | Silent-payment unsubscribe logs the scan secret | open | — |
| H5 | high | IBD reader credits unsolicited data as progress | open | — |
| N1 | medium | Inv getdata does not charge the send budget | fixed | `inv_getdata_charges_send_budget` ([056](./056-inv-getdata-budget.md)) |
| M1 | medium | Block getdata can queue past the send budget | fixed | `getdata_stops_when_send_budget_is_already_over` ([057](./057-block-getdata-budget.md)) |
| M2 | medium | Silent-payment scan span is unbounded when start is set | open | — |
| M3 | medium | RPC listener has no accept timeout; long-poll holds a permit | open | — |
| M4 | medium | fuse8 segment length need not be a power of two | open | — |
| M5 | medium | Class A bulk read ignores the published end | open | — |
| M6 | medium | Testnet milestone is height-only | open | — |
| M7 | medium | Mempool inv is one message per transaction | fixed | `tx_inv_over_one_thousand_is_two_messages` ([058](./058-tx-inv-batch.md)) |
| M8 | medium | Pending blocks and orphans are count-capped only | open | — |
| M9 | high | io_uring drop can free a buffer the kernel still owns | open | — |
| M10 | low | Secret types derive Debug; create-then-chmod | open | — |
| L1 | low | Height-0 BIP68 time lock uses median time 0 | open | — |
| L4 | low | Empty median time panics | open | — |
| L5 | low | Version nonce is not a CSPRNG | open | — |
| L6 | low | Recent-reject set clears at the cap | open | — |
| L8 | low | Manifest and txstat lengths allocate before a size check | open | — |
| L9 | low | Tor control password on argv | open | — |
| L10 | low | Datadir lock follows a symlink | open | — |
| L11 | low | Conf parse errors echo the raw line | open | — |
| L12 | low | Invalid-hash set grows without a cap | open | — |
| L13 | low | Rate window grants two budgets at the boundary | fixed | `rate_limiter_boundary_does_not_grant_a_second_budget` ([059](./059-rate-window-boundary.md)) |
| L14 | low | Mempool expiry runs only on admission | open | — |
| L15 | low | Write jobs form a mutable slice over a shared buffer | open | — |
| L2 | — | P2PKH fast path skips FindAndDelete | rejected | The fast path is the 25-byte template. A DER signature does not fit in that scriptCode, so FindAndDelete cannot change it. |
| L3 | — | Witness-v0 strict DER independent of BIP66 | rejected | BIP141 witness verification is strict DER. Mainnet, testnet, signet, and regtest are unaffected. |
| L7 | low | Rewind deeper than 1024 is refused | won't-fix | `REWIND_MAX_DEPTH` is a deliberate denial-of-service cap. Removing it needs an operator decision. No new knob. |
| L16 | — | Warnet image is pinned by tag | won't-fix | `scripts/core-functional/warnet/Dockerfile` is a lab image, not a Release. |
| eclipse | — | Inverted eviction eclipses the node | rejected | Outbound peers are not eviction candidates. The defect is inbound-slot monopoly, tracked as H2. |
| M2-sh | — | Silent-payment subscribe must require `--sh-index` | rejected | The scan uses the tweak index, not the scripthash index (finding 036). |
| M8-fee | — | Fee and sigop checks at orphan park | rejected | The parent outputs are not available yet. Shape checks already run before park. |
| M6-flag | — | Height-only `--milestone` needs a new flag | rejected | Explicit `--milestone HEIGHT` is already that switch (finding 042). |

Owner: [`quality.md`](../quality.md) **Q-72**.
