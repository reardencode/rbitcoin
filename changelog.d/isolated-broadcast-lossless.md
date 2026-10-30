Fixed

- **Isolated broadcast no longer drops local transactions in a burst.**
  With `--proxy` or `--onion`, local transactions wait for the one-shot
  sender in a 32-slot queue. Each send can wait up to 60 seconds for each
  peer's handshake. Past 32 waiting, the oldest were dropped without a log
  line. Standing peers are never told about them, so they never left the
  node. Now every local transaction still in the mempool is sent once, in
  submit order. A transaction that leaves the mempool first is not sent.
  The sender logs a warning when 32 or more wait, and an info line for
  each peer that took a transaction.
