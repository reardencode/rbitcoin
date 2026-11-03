Fixed

- **`getrawmempool` and `getblocktemplate` answer while catch-up's pool is empty.** A catch-up pool that still holds transactions returns `-10` for both. `generate` during catch-up mines the coinbase only. `-blocksonly` still serves the raw mempool and `generate`, and it returns a permanent error for `getblocktemplate` so a miner does not retry.
