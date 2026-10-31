Changed

- **IBD keeps a `--connect` peer that stalls block download, as in Core.**
  As in [bitcoin/bitcoin#34743](https://github.com/bitcoin/bitcoin/pull/34743),
  a `--connect` or `--trust-peer` peer that trips the IBD stall check is no
  longer disconnected and its address is not cooled. When another
  connected peer could fetch its blocks, its block requests go to the
  other peers, and it is sent no block `getdata` for two minutes on the
  node clock, then it is asked again. INFO `ibd: Pausing block downloads
  from stalling manual peer=<id> for 120 seconds` marks the pause. With no
  such peer (a sole `--connect` or `--trust-peer`, or every other peer is
  paused), it keeps its requests and is not paused, and the stall check
  looks again after another 30 seconds. If every peer still taking block
  requests leaves while a peer is paused, the pause ends at once (INFO
  `ibd: Resuming block downloads from manual peer=<id>: no other peer
  takes block requests`) instead of after two minutes. If a paused peer
  then sends the blocks it was released from, they are accepted (or
  dropped as duplicates) and do not count as unsolicited. Any other
  stalling peer is still disconnected.
- **An IBD peer's answer to a block it was asked for is not unsolicited.**
  When another peer's copy landed first, or the request was moved off a
  paused peer, a later answer from the peer that was asked counted against
  the 16 MB/s unsolicited cap, and a fast peer could be disconnected for
  it. For two minutes after its request is withdrawn, that answer is now
  taken as a body and dropped if it is a duplicate, as in Core.
