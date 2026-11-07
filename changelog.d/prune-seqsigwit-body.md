Fixed

- **`--prune-seqsigwit` no longer keeps `seqsigwit.body`.** The flag stores
  scriptSig and witness only for the last 288 heights
  (`store/seqsigwit.window/{height}.bin`, plus the RAM cache). Enabling it
  on an archive copies that window out and cuts the stem back to its header.
  `txout`, `input`, `txstat`, and block filters stay. Unpruned nodes still
  read `seqsigwit.body`.
