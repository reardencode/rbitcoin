Changed

- **Regtest and testnet header batches reuse the min-difficulty walk.** An
  easy header no longer walks back to the retarget boundary when its
  parent in the same batch already did. Mainnet still takes the parent
  bits directly.
