Changed

- **A red Core functional script changes the node only when a peer would
  miss a block or a transaction, or a documented RPC code would change.**
  Message counts and grepped sentences stay in the shim, the RPC proxy, or
  the debug-log map. Package dialect and the tip-idle wait stay off unless
  the harness sets them. A peer fee filter that is above a transaction
  still drops that transaction for the session, as Core does.
- **A one-transaction `generateblock` with a missing input no longer quotes
  Core's `CheckTxInputs` clause.** The code stays `-25` and the reason
  stays `bad-txns-inputs-missingorspent`, and the message still names the
  transaction. The functional RPC proxy adds the clause.
- **A local transaction that confirms before a peer fetches it, and a bad
  v2 handshake, log a native sentence.** The transaction still leaves the
  unbroadcast set, and the handshake still disconnects. The functional
  debug-log map still emits Bitcoin Core's sentences for those lines.
- **An inv of a tip starts the same 200ms hold as a header.** A burst of
  tips that are not descendants of that inv goes out as one announcement.
  The inv still does not mark the header cursor, so the block after a
  reorg longer than 8 blocks stays an inv. Offering that same tip again
  sends nothing.
