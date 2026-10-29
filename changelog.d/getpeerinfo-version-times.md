Fixed

- **`getpeerinfo` rows carry `version`, `conntime`, `lastsend` and
  `lastrecv`.** NBXplorer (under BTCPay Server) reads them through
  NBitcoin's `GetPeersInfoAsync`, which threw on rows without them (#1248).
  `version` is the peer's VERSION protocol version (`0` before VERSION).
  `conntime` is set once when the connection is created and is kept when
  the handshake completes. `lastrecv` and `lastsend` are when a byte was
  last read or written on the socket, BIP324 handshake bytes included,
  and stay `0` until then, as in Core. An outbound row still in its
  handshake now counts those bytes in `bytesrecv` / `bytessent`, as an
  inbound row already did.
