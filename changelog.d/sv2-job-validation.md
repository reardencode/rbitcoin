Added

- **SV2 TP: custom job validation for Job Declarator Servers.** A TDP
  client that sets `SetupConnection` flag bit 0 (`REQUIRES_JOB_VALIDATION`)
  can send `ProposeTemplate` (proposed TDP messages 0x77–0x7b, sv2-spec
  discussion #239) with the `DeclareMiningJob` fields relayed unchanged.
  The node rebuilds the placeholder coinbase from the declared prefix and
  suffix, resolves the declared wtxids against its mempool, asks for the
  ones it lacks with `ProvideMissingTransactions` and takes them back in
  `ProvideMissingTransactions.Success` (the Job Declaration Protocol's own
  shapes, so a JDS relays both unchanged; the proposal is held up to 30 s,
  at most eight per connection), checks the job as a block on its tip, and
  answers that tip,
  the fee total of the declared transactions, and a template id that
  `SubmitSolution` accepts like one of the node's own templates; the job is
  retained like one too (same ring, same stale grace). Duplicated,
  undeclared, or malformed input is refused before anything is decoded.
  Validation runs off the session loop, up to four at once per
  connection, so a `SubmitSolution` or a tip push never waits behind
  another client's proposal.
