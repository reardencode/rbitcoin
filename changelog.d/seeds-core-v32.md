Changed

- **DNS and fixed seeds match Bitcoin Core v32.0.** The DNS seed lists for
  mainnet, testnet3, and signet are Core's lists in Core's order.
  `seed.bitcoin.sipa.be`, `seed.bitcoinstats.com`,
  `dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us`, and
  `testnet-seed.bitcoin.schildbach.de` are gone; the `achownodes.xyz` seeds
  are new. The fixed seeds were two hostnames resolved through DNS. They are
  now Core's `contrib/seeds` lists (IPv4, IPv6, Tor v3, I2P, CJDNS; 2,057
  mainnet entries), embedded under `crates/rbitcoin-net/seeds/` and
  refreshed with `scripts/core-fixed-seeds.sh COMMIT`. As in Core, after the
  DNS seeds a reachable network with no address in the peer book gets that
  network's fixed seeds. `--only-net onion` gets only onion seeds. A
  network this process cannot dial gets none.
