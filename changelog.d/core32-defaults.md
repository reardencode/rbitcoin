Changed

- **Default milestones match Bitcoin Core 32.1.** An omitted `--milestone` on mainnet anchors block 966143 (`00000000000000000000748969ec33043c0e52a763c6dd5193861f559f2c72e3`) and on testnet3 anchors block 5128859 (`00000000b318a3703d14a844c55ef507f4c2fc8f8766e24271fd43c180c51637`), Core’s `defaultAssumeValid` blocks. `--min-chain-work` defaults remain Core 32.1 `nMinimumChainWork` on mainnet, testnet3, and testnet4. Signet and testnet4 still check every script. The skip is still the two header-path lookups. It is not Core’s assumevalid predicate.
