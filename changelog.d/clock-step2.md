Changed

- **net: PeerHub uses NodeClock, drop second mock battery (Step 2).** PeerHub no longer has its own mock clock; it holds NodeClock. `set_mock` sets the clock and calls `on_clock_jump()` which requests tx INVs, runs heartbeat, then queues self-announce on live peers. TxRelay still has its own mock clock; setmocktime still notifies it. That is Step 3.
