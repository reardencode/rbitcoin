Security

- Cap the parent-request tracker per peer and process-wide, and
  re-request a wtxid announcement as a wtxid.
- Charge outbound getdata and tx announcements against the per-peer send
  budget, and stop serving blocks once that budget is already over.
- The per-peer rate window keeps the previous second so a boundary does
  not grant a second full budget.
- Count v2 decoy packets and unknown message types in the per-peer rate
  window on tip-follow and IBD, and disconnect once that window is over.
- Batch mempool transaction announcements into one inv per thousand,
  still charged against the per-peer send budget.
