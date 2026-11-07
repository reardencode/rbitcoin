Changed

- **Electrum and Esplora go on Tor and I2P only when asked.** Before, a
  listening Electrum was always published as an onion once `--tor-control`
  was set, Esplora too unless `--esplora-onion=0`, and `--i2p-accept-incoming`
  gave both their own I2P destination. Now each is a switch, **off by
  default**: `--electrum-onion`, `--esplora-onion`, `--electrum-i2p`,
  `--esplora-i2p` (config `electrum_onion=`, `esplora_onion=`,
  `electrum_i2p=`, `esplora_i2p=`). `--i2p-accept-incoming` is P2P only.
  **Upgrading:** a node that relied on `--tor-control` or
  `--i2p-accept-incoming` alone to publish its wallet services stops
  publishing them until the matching switch is set; the saved keys under
  `onion/` and `i2p/` are kept, so the addresses come back unchanged. A
  switch needs its overlay (`--tor-control` or `--i2p-sam`) and a TCP
  listener on `127.0.0.1` or `0.0.0.0`, or the node refuses to start.
- **NixOS.** `electrum.hiddenService` now passes `--electrum-onion` (it had
  no effect before), and new `electrum.i2p` / `esplora.i2p` pass the I2P
  switches. A NixOS node that set `tor.control` or `p2p.listenOnion` without
  `hiddenService` no longer publishes its wallet onions.
