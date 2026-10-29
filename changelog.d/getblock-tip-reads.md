Fixed

- **`getblock` reads the tip once and reports read errors.**
  `confirmations` and `nextblockhash` now come from one sample of the tip,
  so a block that connects during the call cannot pair one tip's
  `nextblockhash` with another tip's `confirmations`. If the read that
  checks the block is still active fails, the call returns Core's `-32603`
  instead of the disconnected-block answer.
- **`getblock` verbosity 2 reads less.** The `fee` now reads only each
  parent output. It no longer reads each parent's own inputs to build a
  `prevout` that verbosity 2 does not return.
- **The stale-branch `prevout` walk reaches its cap.** A stale branch
  exactly 10,000 blocks deep now places its parents. A deeper branch fails
  as documented in `docs/rpc.md`.
