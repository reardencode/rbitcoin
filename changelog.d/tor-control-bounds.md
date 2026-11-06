Fixed

- **`--tor-control` no longer waits without a deadline or reads without a
  bound** (#1354). A control port that accepted the connection and never
  answered held the start before RPC came up, logged nothing, and SIGTERM did
  not end it. A reply line without end grew memory until the OOM killer ran.
  Connecting and each control command now give up after 20 s with an error
  naming `--tor-control`. A reply line over 64 KiB or a reply over 1 MiB ends
  the start, and SIGTERM during the Tor step exits at once. The same bound
  covers the Electrum and Esplora onions added after catch-up.
