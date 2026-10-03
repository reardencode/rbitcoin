Security

- Omitted `--milestone` on testnet checks every script. An explicit
  `--milestone HEIGHT` stays height-only, and omitted mainnet stays
  anchored. NixOS `services.rbitcoin.milestone` passes the flag when set.
- An empty median-time window is an error. A height-0 BIP68 time lock
  uses the genesis median.
- The version nonce comes from the CSPRNG. The recent-reject set and the
  invalid-hash set stop at 4096 entries instead of clearing.
- Mempool expiry walks at most 256 entries per call and also runs on the
  headers poll, so a quiet pool still expires.
- A tip-follow pending block or held body larger than 4,000,000 bytes is
  not parked. One peer's orphans stay within that peer's reserve.
- `StoreSecret` and RPC auth debug output is redacted. `store.secret`
  and the API log are created mode 0600. A Tor control password that
  contains CR, LF, or NUL is refused, and passing it on the command
  line warns once. A conf error names the file and line and does not
  echo the raw line. A group- or world-readable RPC cookie warns once.
