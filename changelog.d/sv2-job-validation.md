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
  retained like one too (same ring, same stale grace). A repeated request id or wtxid is refused as the frame
  arrives, and a provide that is short or carries a transaction nobody asked
  for is refused before any of it is decoded or copied. Every non-coinbase
  transaction of the job is script-checked, the supplied ones too.
  Validation runs off the session loop, so a `SubmitSolution` or a tip
  push never waits behind another client's proposal. Across all
  connections, at most a quarter of the node's blocking-thread pool (at
  least one) validates at once, and a validation already running keeps its
  share until it finishes even if its connection closes; the blocking work cannot be
  aborted once started. A waiting proposal takes a freed share in arrival
  order whatever its own connection is doing, so a client that reads slowly
  delays only itself. That reserves threads from proposals but does not stop
  other work from using the pool.
  `/metrics` `rbitcoin_sv2_validations_running` and the `tip: perf`
  `sv2_validating` field show how many run. A connection holds at most 16 accepted
  proposals and 16 MiB of them (wtxids, coinbase split, supplied
  transactions) at once; one past either is answered
  `job-validation-unavailable` and the connection keeps serving, as it
  does for a proposal whose validation cannot read the chain tip or the
  chain data its check needs. A client
  frame over 65557 bytes closes a connection that did not set the flag; only a
  flagged one may send the ~2.3 MB `ProposeTemplate` or ~4.2 MB provide.
  `SetupConnection.Error.flags` names only the unsupported bits.
- **SV2 TP: a validated job's solution is rebuilt with the `nBits` its
  timestamp needs.** A JDC hashes the `nBits` its own template provider
  sent, which can differ from the ones this node validated the job with on a
  min-difficulty network, and a validating connection never receives a
  `SetNewPrevHash`. `SubmitSolution` for a validated job now takes the
  `nBits` consensus requires of a child of the job's parent at the
  submitted time, and checks proof of work against that exact header before
  the block is submitted. A solution for a pushed template keeps the `nBits`
  its `SetNewPrevHash` announced.
- **SV2 TP: a job-validation-only connection needs no constraints.** A TDP
  client that sets `REQUIRES_JOB_VALIDATION` is set up once
  `SetupConnection.Success` is sent. It may never send
  `CoinbaseOutputConstraints`, is then sent no `NewTemplate` or
  `SetNewPrevHash`, and is no longer closed at the 10 s setup deadline; it
  proposes jobs, reads their transactions, and submits solutions, and
  constraints sent later start the template stream. Its validated jobs retire
  after the stale grace once the tip moves off their parent, like any
  session's. A session without the flag keeps the deadline. `--sv2-tp-idle-timeout`, off by default, starts at
  `SetupConnection.Success` for such a connection; a value under the 30 s
  provide hold closes a Job Declarator Server that is quietly waiting for its
  client.
