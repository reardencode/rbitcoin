Fixed

- **Scripthash history follows `--sh-index`.** After the index has been
  built, a start without the flag kept answering `get_history`,
  `get_balance`, and `listunspent` from the frozen index. Those methods
  now fail with `scripthash index disabled`. Turning the flag back on
  still serves the index that is already on disk.
