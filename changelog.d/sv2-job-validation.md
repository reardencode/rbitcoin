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
  Validation runs off the session loop, so a `SubmitSolution` or a tip
  push never waits behind another client's proposal. Across all
  connections, at most a quarter of the node's blocking-thread pool (at
  least one) validates at once, and a validation already running keeps its
  share until it finishes even if its connection closes; that reserves
  threads from proposals but does not stop other work from using the pool.
  `/metrics` `rbitcoin_sv2_validations_running` and the `tip: perf`
  `sv2_validating` field show how many run. A connection holds at most 16 accepted
  proposals and 16 MiB of them (wtxids, coinbase split, supplied
  transactions) at once; one past either is answered
  `job-validation-unavailable` and the connection keeps serving, as it
  does for a proposal whose validation cannot read the chain tip.
- **SV2 TP: a validated job's solution is rebuilt with the `nBits` its
  timestamp needs.** A JDC hashes the `nBits` its own template provider
  sent, which can differ from the ones this node validated the job with on a
  min-difficulty network, and a validating connection never receives a
  `SetNewPrevHash`. `SubmitSolution` for a validated job now takes the
  `nBits` consensus requires of a child of the job's parent at the
  submitted time, and checks proof of work against that exact header before
  the block is submitted. A solution for a pushed template keeps the `nBits`
  its `SetNewPrevHash` announced.
