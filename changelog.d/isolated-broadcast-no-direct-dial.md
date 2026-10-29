Fixed

- **Isolated broadcast never connects directly.** With `--onion` set and
  no `--proxy`, the one-shot broadcast of your own transaction could pick
  a clearnet peer and connect to it straight from your IP. It now only
  reaches IPv4/IPv6 peers through `--proxy`, and never uses CJDNS peers.
