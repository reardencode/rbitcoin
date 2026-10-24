Fixed

- **The Esplora request limit bounds the listener, not each route.**
  axum's `Router::layer` wraps every route on its own, so
  `ConcurrencyLimitLayer` gave each of the listener's routes its own 256
  permits: in practice no limit. The limit is now one semaphore shared by
  every route and the fallback. Requests over it wait for a slot; they are
  not refused. The request timeout now covers that wait too, so a queue of
  slow requests ahead cannot hold a later one past one timeout (**408**).
  The `/blindbit/v1/` routes share this limit too. A BlindBit request waits
  for its own permit first, so one queued there holds no listener slot.

Added

- **`--esplora-max-inflight N`** (conf `esplora_max_inflight=`, NixOS
  `services.rbitcoin.esplora.maxInflight`) sets that limit. The default stays
  256. A busy public listener may want more. Values above tokio's
  semaphore limit are refused at startup.
