Changed

- **Transaction-id lookup during initial download reads the open `tx.head` segment from a shared memory map.** A probe no longer reads a 4 KiB page per key. Each slot also stores a short fingerprint of the id, so most misses skip the full id read. Signet initial download on a Mac mini ran about 20% faster. Sealed segments are unchanged.
- **`tx.head` metadata is version 2.** An existing head opens as before. The first open writes fingerprints into the open segment and records that. A downgrade to a binary that expects version 1 rebuilds `tx.head` from the chain data.
- **`tx.head` slots are 4 bytes.** The 8-byte width is gone. `RBITCOIN_TX_HEAD_BITS` cannot be set above 32.
