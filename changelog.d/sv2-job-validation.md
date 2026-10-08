Added

- **SV2 TP: custom job validation for Job Declarator Servers.** A TDP
  client that sets `SetupConnection` flag bit 0 (`REQUIRES_JOB_VALIDATION`)
  can send `ProposeTemplate` (proposed TDP messages 0x77–0x7a, sv2-spec
  discussion #239) with the `DeclareMiningJob` fields relayed unchanged.
  The node rebuilds the placeholder coinbase from the declared prefix and
  suffix, resolves the declared wtxids against its mempool, asks for the
  ones it lacks, checks the job as a block on its tip, and answers that tip,
  the fee total of the declared transactions, and a template id that
  `SubmitSolution` accepts like one of the node's own templates; the job is
  retained like one too (same ring, same stale grace). Duplicated,
  undeclared, or malformed input is refused before anything is decoded.

Changed

- **`getblocktemplate` proposal mode rejects an overpaying coinbase** with
  `bad-cb-amount`, as Bitcoin Core does.
