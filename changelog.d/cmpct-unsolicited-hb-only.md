Changed

- **Unsolicited compact blocks are reconstructed only from high-bandwidth
  peers.** As in Core
  ([bitcoin/bitcoin#32606](https://github.com/bitcoin/bitcoin/pull/32606)),
  a `cmpctblock` this session did not ask for is reconstructed only when we
  sent that peer `sendcmpct(1)`. From any other peer it is a header
  announcement: the header is stored and the block is fetched with a
  full-block `getdata`, with no `getblocktxn` and no mempool walk. A
  `cmpctblock` from a peer that never sent `sendcmpct` version 2 is
  ignored, as one already was under `-blocksonly`.
