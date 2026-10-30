Added

- **`getblockchaininfo` `size_on_disk` can be 30 seconds stale.** The node reuses the last datadir walk for 30 seconds. A new or grown store file shows up on the next walk after that interval.
