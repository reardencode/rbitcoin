Changed

- **SV2 builds one template at a time for the same tip, coinbase budget, time, and difficulty.** A second session with the same previous-block hash, coinbase size, coinbase sigops, `nBits`, header time, and mempool template-update counter waits and reuses that build. A different budget, time, difficulty, or template-update bump builds on its own and does not evict the others. A build that does not produce a template is not reused.
