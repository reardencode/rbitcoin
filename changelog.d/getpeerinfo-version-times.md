Fixed

- **`getpeerinfo` rows carry `version`, `conntime`, `lastsend` and
  `lastrecv`.** NBXplorer (under BTCPay Server) reads them through
  NBitcoin's `GetPeersInfoAsync`, which threw on rows without them (#1248).
  `version` is the peer's VERSION protocol version (`0` on a row still
  connecting). `conntime` is when the session registered, after VERSION.
  `lastrecv` moves on every message read and `lastsend` each time the
  writer finishes a message; both start at `conntime`.
