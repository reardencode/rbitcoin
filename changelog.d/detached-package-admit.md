Fixed

- **A dropped package or test-accept request still rolls the mempool back.** Package accept, a one-parent-one-child admit, `submitpackage`, and a multi-tx `testmempoolaccept` finish abandon, parent rollback, the final trim, and removal of the test inserts after the caller is gone.
- **A queued decode does not pause the next TCP read or trip the ping timeout.** Bytes already on the socket, including a ping or a pong, are read while earlier frames wait for a decode permit. The ping timeout stays suspended until that queue is empty.
