Fixed

- **Peer connections keep reading while a block, a header batch, or a compact block is rebuilt.** That work runs on the blocking pool, under the same limit as block decode. Encoding eight headers or fewer stays on the writer. A block and a 2,000-header reply still move off it.
- **A full tip-accept queue waits for a slot.** It does not spin a network thread. Each connection that found the queue full gets a turn when a slot opens.
- **A script batch wakes one worker per chunk.** Idle script workers stay parked once those chunks are taken. A larger batch still uses the whole pool.
- **A failure reading an announced tip transaction answers `notfound` and keeps the peer.** A failed join of that work still ends the session.
- **High-bandwidth relay builds the compact block off the network thread, and only when a peer would be offered the block.** A missing body still goes out as headers. A failed build is logged and that announcement is skipped. A failed compact tip announcement still ends that session. An unsolicited compact block stores its header on that same pool.
- **Header reads for initial download no longer stall the header thread.** Choosing which peer downloads blocks, and checking a candidate fork, read the confirmed header without holding the coordinator lock. A straight extension is not rewound. The commit is skipped when the header thread has already moved the tip to a different block.
- **A headers batch that was already read is stored even when the send budget is spent.** The node can ask again on a later poll. Follow-up block and header requests wait until the writer drains. New `getheaders` and `getblocks` requests still stop at that budget.
- **A block is marked in flight only when its request is queued.** Two peers can still look at the same announcement. If the queue fails, the mark is released. A header job that does not finish on the session does not leave the hash stuck.
