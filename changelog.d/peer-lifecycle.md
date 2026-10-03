Security

- Inbound eviction keeps a share of the longest-connected peers and
  disconnects the newest peer in the largest netgroup. The netgroup is
  fixed when the peer is accepted.
- A misbehavior disconnect refuses that address for one day, in memory
  only. A netgroup that just lost an inbound slot waits ten minutes.
  The set does not grow past its cap.
- During initial download, only a block this node requested moves the
  stall clock or is queued. Other frames are rate-limited. Light
  decodes do not wait on the reader.
