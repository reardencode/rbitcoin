Changed

- **SOCKS dials get 30 seconds to connect.** Each isolated SOCKS dial builds its own Tor circuit, and a 32-dial wave queues in Tor for longer than the 8 second clearnet bound, so whole waves timed out. Clearnet dials through `--proxy` and onion dials now get at least 30 seconds. Direct and CJDNS dials keep 8 seconds. I2P keeps 90 seconds.
