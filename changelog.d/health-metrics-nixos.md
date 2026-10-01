Added

- **More Prometheus gauges.** `/metrics` also exposes verification progress,
  tip age, difficulty, peer counts by network, outbound time offset, P2P
  byte totals, and mempool min fee, weight cap, orphans, and unbroadcast
  count. Each one is a value RPC already publishes.
- **NixOS health and metrics.** `services.rbitcoin.health.enable` passes
  `--health-listen` (default `127.0.0.1:9332`). `services.rbitcoin.metrics`
  passes `--metrics` and adds a Prometheus scrape job when
  `services.prometheus.enable` is set.
