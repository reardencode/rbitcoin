Fixed

- **A local transaction that a peer already requested stays broadcast.**
  `sendrawtransaction` and `submitpackage` record the unbroadcast set after
  the tx is announced. A peer that getdatas it in that window used to be
  ignored, and the later note put the tx back. `getrawmempool` and
  `getmempoolentry` could then disagree on `unbroadcast`. A getdata in that
  window now wins.
- **A transaction skipped for a peer's feefilter is not announced when the
  filter drops.** Bitcoin Core removes it from that peer's to-send set.
  Announcing it again made `p2p_feefilter.py` wait on an inv set that
  included the transactions the filter had already rejected.
