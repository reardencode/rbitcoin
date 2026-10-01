Added

- **More Prometheus gauges.** `/metrics` also exposes verification progress,
  tip age, difficulty, peer counts by network, outbound time offset, P2P
  byte totals, and mempool min fee (sat/vB), weight cap, orphans, and
  unbroadcast count. Fee rates on this scrape are sat/vB. The Core RPC
  fields stay BTC/kvB.
- **NixOS health and metrics.** `services.rbitcoin.health.enable` passes
  `--health-listen` (default `127.0.0.1:9332`). `services.rbitcoin.metrics`
  passes `--metrics` and adds a Prometheus scrape job when
  `services.prometheus.enable` is set.
