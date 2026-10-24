Fixed

- **Concurrent regtest `generate*` / `generateblock` calls no longer mine a
  transaction twice.** Each call selected pool transactions and then connected
  its block with no lock across the two, so a second call could select a
  transaction the first had just confirmed and fail with `bad-txns-BIP30`.
  Mining calls now run one at a time, as Core's do under cs_main.
