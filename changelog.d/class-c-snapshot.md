Changed

- **One thread writes each in-memory chain table.** Confirm, accepting a tip block, and startup are the writers. Clearing archived bodies waits until the in-flight tip flush finishes. A block body can still be appended while that flush runs. If the block is then rejected, its header range is stored after the flush, so a retry still finds the body. Sync of that chain data to disk stays on its own thread, about every 10 minutes. The in-memory tables still flush once per confirm batch.
- **Readers of those tables do not take a lock.** A reader that overlaps a write retries, and it does not observe a new length before the bytes are stored. Growing a table keeps the previous buffer until readers finish with it. The transaction-id bitset is one 256 MiB reservation. Growth commits the used prefix and does not keep a retired copy.
- **A script-check wave is not finished while a worker still holds a chunk.**
- **A disk-only append publishes its length after the bytes.** A reader that sees the new length does not read zeros. A read that races a shorten is empty when the index is past the new length.
