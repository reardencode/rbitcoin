Fixed

- **`getblock` verbosity 3 returns `vin[].prevout`.** Verbosity 3 and above
  returned the verbosity 2 output, so Silent Payments (BIP 352) scanners and
  prevout-based indexers found no eligible inputs. Each non-coinbase input
  now carries `prevout` (`generated`, `height`, `value`, `scriptPubKey`) as
  in Core, also for a block disconnected by a reorg. Every verbosity >= 1
  now carries Core's `coinbase_tx` object. Verbosity 2 `fee` comes from the
  same stored prevouts, so a held never-connected body omits it, as Core
  does without undo data.
