Added

- **Electrum and Esplora can each stay off Tor and I2P.** `--electrum-onion=0`
  keeps Electrum off the onion `--tor-control` publishes, as
  `--esplora-onion=0` already did for Esplora. `--electrum-i2p=0` and
  `--esplora-i2p=0` keep that service off I2P under `--i2p-accept-incoming`.
  All four default to on, so an existing node publishes what it did before.
  Config keys: `electrum_onion=`, `electrum_i2p=`, `esplora_i2p=`.
