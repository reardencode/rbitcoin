Changed

- **A red Core functional script changes the node only when a peer would
  miss a block or a transaction, or a documented RPC code would change.**
  Message counts and grepped sentences stay in the shim, the RPC proxy, or
  the debug-log map. Package dialect and the tip-idle wait stay off unless
  the harness sets them. A peer fee filter that is above a transaction
  still drops that transaction for the session, as Core does.
