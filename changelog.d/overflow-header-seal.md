Fixed

- **A missed overflow-header write does not seal the tip.**
  Open keeps the creates the durable locator and checkpoint headers still
  name. A withheld overflow row cuts only the create it belongs to. A
  disconnect that dies while shortening those files reopens at that prefix
  instead of refusing the datadir. Input edges for the kept creates stay
  put when that shorten is replayed.
