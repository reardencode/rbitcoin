Changed

- **The addr-fetch journey waits for the learned reply, not a live session.**
  `p2p_timeout_getaddr_and_keepalive_ping` polled for the AddrFetch session
  to appear and then close within 3 s. When the test task was starved (as
  under coverage), the whole session could run between two polls and the
  test failed with `saw=false`. It now waits until the node has learned an
  addr list longer than one and no AddrFetch session remains, with a longer
  deadline under `CARGO_LLVM_COV`.
