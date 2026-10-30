Changed

- **SV2 builds one template at a time for the same tip and coinbase budget.** A second session with the same previous-block hash, coinbase size, coinbase sigops, and mempool template-update counter waits and reuses that build. A different budget or a template-update bump builds again. A build that does not produce a template is not reused.
