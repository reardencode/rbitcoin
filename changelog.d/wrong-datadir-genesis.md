Fixed

- **A datadir for another chain is refused.** `store/meta` still records
  magic and schema, not the network. When block 0 is already on disk, a
  start whose genesis hash does not match that block stops before peers,
  the peers file, and RPC. The error names the stored genesis and the
  started genesis. An empty datadir, and a datadir for the same chain,
  still open.
