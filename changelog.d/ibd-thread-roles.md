Changed

- **The scripthash index thread starts when that index is at the tip.** With `--sh-index`, a head that is already durable starts it before catch-up. A catch-up that has to build the index starts it only after that build. It stays down when the build is cancelled or fails, and when the index is off.
- **Heavy CPU leaves the blocking pool for the script workers (`rbtc-scripts-*`).** That is a heavy v2 encode, compact-block short ids after the body is in hand, and an Electrum or Esplora JSON body of at least 4 KiB, including `GET /block-template`. Shorter encodes stay on the caller. Block and header decode stay on the blocking pool. Block templates still send `cache-control: no-store`.
- **A panic in one script job does not kill the worker.** A JSON encode that is dropped is an error, not `{}`. A compact-block encode that is dropped is a peer protocol error, not a fallback to headers.
- **Initial-download tip flushes share one thread.** Tip mode still flushes on the thread that accepts the tip.
